import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)

from app.observability import MetricsRegistry
from app.rate_limit import (
    FixedWindowRateLimiter,
    RateLimitDecision,
    rate_limit_subject,
)
from app.runtime_config import RuntimeSettings


LOGGER = logging.getLogger("decaustrum.http")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
JSON_BODY_METHODS = {"POST", "PUT", "PATCH"}
CORS_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
}
CORS_HEADERS = {
    "accept",
    "content-type",
    "idempotency-key",
    "x-admin-actor",
    "x-admin-api-key",
    "x-api-key",
    "x-audit-reason",
    "x-request-id",
}


class RequestBodyTooLarge(Exception):
    pass


class InvalidContentLength(Exception):
    pass


def _request_id(headers: Headers) -> str:
    candidate = headers.get("x-request-id")

    if (
        candidate is not None
        and REQUEST_ID_PATTERN.fullmatch(candidate) is not None
    ):
        return candidate

    return str(uuid4())


def _host_without_port(host_header: str) -> str:
    value = host_header.strip().lower().rstrip(".")

    if value.startswith("["):
        closing_bracket = value.find("]")

        if closing_bracket == -1:
            return ""

        return value[1:closing_bracket]

    if value.count(":") == 1:
        host, possible_port = value.rsplit(":", 1)

        if possible_port.isdigit():
            return host

    return value


def _host_allowed(host: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        normalized = pattern.lower().rstrip(".")

        if normalized.startswith("*."):
            suffix = normalized[1:]

            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == normalized:
            return True

    return False


def _origin_allowed(
    origin: str,
    allowed_origins: tuple[str, ...],
) -> bool:
    normalized = origin.rstrip("/")
    return any(
        normalized == configured.rstrip("/")
        for configured in allowed_origins
    )


def _early_route(path: str) -> str:
    if path == "/v1/authorize":
        return "/v1/authorize"

    if path.startswith("/v1/admin/"):
        return "/v1/admin/*"

    if path.startswith("/v1/"):
        return "/v1/*"

    if path in {
        "/health",
        "/health/live",
        "/health/ready",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    }:
        return path

    return "unmatched"


def _resolved_route(scope: Scope) -> str:
    route = scope.get("route")
    route_path = getattr(route, "path", None)

    if isinstance(route_path, str):
        return route_path

    return _early_route(scope.get("path", ""))


def _rate_policy(
    *,
    scope: Scope,
    headers: Headers,
    settings: RuntimeSettings,
) -> tuple[str, str | None, int] | None:
    path = scope.get("path", "")

    if path == "/v1/authorize":
        return (
            "authorization",
            headers.get("x-api-key"),
            settings.authorization_rate_limit,
        )

    if path.startswith("/v1/admin/") or path == "/metrics":
        return (
            "admin",
            headers.get("x-admin-api-key"),
            settings.admin_rate_limit,
        )

    if path.startswith("/v1/"):
        return (
            "tenant",
            headers.get("x-api-key"),
            settings.tenant_rate_limit,
        )

    return None


def _rate_headers(
    decision: RateLimitDecision | None,
) -> dict[str, str]:
    if decision is None:
        return {}

    return {
        "RateLimit-Limit": str(decision.limit),
        "RateLimit-Remaining": str(decision.remaining),
        "RateLimit-Reset": str(decision.reset_at),
    }


class SecurityObservabilityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: RuntimeSettings,
        metrics: MetricsRegistry,
        rate_limiter: FixedWindowRateLimiter,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.app = app
        self.settings = settings
        self.metrics = metrics
        self.rate_limiter = rate_limiter
        self.clock = clock

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = _request_id(headers)
        scope.setdefault("state", {})["request_id"] = request_id
        method = scope.get("method", "UNKNOWN").upper()
        path = scope.get("path", "")
        started_at = self.clock()
        status_code = 500
        rate_decision = None
        origin = headers.get("origin")
        allowed_origin = (
            origin
            if origin is not None
            and _origin_allowed(
                origin,
                self.settings.cors_allowed_origins,
            )
            else None
        )
        self.metrics.request_started()

        async def finish() -> None:
            duration_seconds = max(0.0, self.clock() - started_at)
            route = _resolved_route(scope)

            if status_code == 401:
                self.metrics.record_security_event(
                    "authentication_failed"
                )

            self.metrics.request_finished(
                method=method,
                route=route,
                status_code=status_code,
                duration_seconds=duration_seconds,
            )
            principal_type = scope.get("state", {}).get(
                "principal_type"
            )
            level = (
                logging.ERROR
                if status_code >= 500
                else logging.WARNING
                if status_code >= 400
                else logging.INFO
            )
            LOGGER.log(
                level,
                "http_request_completed",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "route": route,
                    "status_code": status_code,
                    "duration_ms": round(
                        duration_seconds * 1_000,
                        3,
                    ),
                    "principal_type": principal_type,
                },
            )

        try:
            host_values = headers.getlist("host")
            host = _host_without_port(
                host_values[0] if len(host_values) == 1 else ""
            )

            if not _host_allowed(host, self.settings.trusted_hosts):
                status_code = 400
                self.metrics.record_security_event("invalid_host")
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="invalid_host",
                    message="Request host is not trusted.",
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            if self.settings.enforce_https and scope.get("scheme") != "https":
                status_code = 400
                self.metrics.record_security_event("https_required")
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="https_required",
                    message="HTTPS is required.",
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            if origin is not None and allowed_origin is None:
                status_code = 403
                self.metrics.record_security_event("cors_origin_denied")
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="cors_origin_denied",
                    message="Request origin is not allowed.",
                    request_id=request_id,
                    scheme=scope.get("scheme", "http"),
                )
                return

            if (
                method == "OPTIONS"
                and allowed_origin is not None
                and headers.get("access-control-request-method")
                is not None
            ):
                requested_method = headers.get(
                    "access-control-request-method",
                    "",
                ).upper()
                requested_headers = {
                    value.strip().lower()
                    for value in headers.get(
                        "access-control-request-headers",
                        "",
                    ).split(",")
                    if value.strip()
                }

                if (
                    requested_method not in CORS_METHODS
                    or not requested_headers <= CORS_HEADERS
                ):
                    status_code = 403
                    self.metrics.record_security_event(
                        "cors_preflight_denied"
                    )
                    await self._send_json_error(
                        send=send,
                        status_code=status_code,
                        code="cors_preflight_denied",
                        message="CORS preflight is not allowed.",
                        request_id=request_id,
                        origin=allowed_origin,
                        scheme=scope.get("scheme", "http"),
                    )
                    return

                status_code = 204
                await self._send_empty(
                    send=send,
                    status_code=status_code,
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            try:
                content_length = self._content_length(headers)
            except InvalidContentLength:
                status_code = 400
                self.metrics.record_security_event(
                    "invalid_content_length"
                )
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="invalid_content_length",
                    message="Content-Length must be a non-negative integer.",
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            if content_length > self.settings.max_request_body_bytes:
                status_code = 413
                self.metrics.record_security_event("request_body_too_large")
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="request_body_too_large",
                    message="Request body exceeds the configured limit.",
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            has_body = (
                content_length > 0
                or headers.get("transfer-encoding") is not None
            )

            if (
                path.startswith("/v1/")
                and method in JSON_BODY_METHODS
                and has_body
                and not self._is_json_content_type(headers)
            ):
                status_code = 415
                self.metrics.record_security_event(
                    "unsupported_content_type"
                )
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="unsupported_content_type",
                    message="Request body must use application/json.",
                    request_id=request_id,
                    origin=allowed_origin,
                    scheme=scope.get("scheme", "http"),
                )
                return

            if self.settings.rate_limit_enabled:
                policy = _rate_policy(
                    scope=scope,
                    headers=headers,
                    settings=self.settings,
                )

                if policy is not None:
                    policy_name, credential, limit = policy
                    client = scope.get("client")
                    client_host = (
                        client[0]
                        if client is not None
                        else None
                    )
                    client_decision = self.rate_limiter.check(
                        policy=f"{policy_name}:client",
                        subject=rate_limit_subject(
                            credential=None,
                            client_host=client_host,
                        ),
                        limit=limit,
                        window_seconds=(
                            self.settings.rate_limit_window_seconds
                        ),
                    )
                    rate_decision = client_decision

                    if client_decision.allowed and credential:
                        credential_decision = self.rate_limiter.check(
                            policy=f"{policy_name}:credential",
                            subject=rate_limit_subject(
                                credential=credential,
                                client_host=client_host,
                            ),
                            limit=limit,
                            window_seconds=(
                                self.settings.rate_limit_window_seconds
                            ),
                        )

                        if (
                            not credential_decision.allowed
                            or credential_decision.remaining
                            < client_decision.remaining
                        ):
                            rate_decision = credential_decision

                    if not rate_decision.allowed:
                        status_code = 429
                        self.metrics.record_security_event(
                            "rate_limit_exceeded"
                        )
                        await self._send_json_error(
                            send=send,
                            status_code=status_code,
                            code="rate_limit_exceeded",
                            message="Request rate limit exceeded.",
                            request_id=request_id,
                            origin=allowed_origin,
                            rate_decision=rate_decision,
                            scheme=scope.get("scheme", "http"),
                            extra_headers={
                                "Retry-After": str(
                                    rate_decision.retry_after
                                )
                            },
                        )
                        return

            received_bytes = 0
            response_started = False

            async def limited_receive() -> Message:
                nonlocal received_bytes
                message = await receive()

                if message["type"] == "http.request":
                    received_bytes += len(message.get("body", b""))

                    if (
                        received_bytes
                        > self.settings.max_request_body_bytes
                    ):
                        raise RequestBodyTooLarge

                return message

            async def secured_send(message: Message) -> None:
                nonlocal status_code, response_started

                if message["type"] == "http.response.start":
                    response_started = True
                    status_code = int(message["status"])
                    mutable_headers = MutableHeaders(scope=message)
                    self._apply_response_headers(
                        headers=mutable_headers,
                        request_id=request_id,
                        scheme=scope.get("scheme", "http"),
                        origin=allowed_origin,
                        rate_decision=rate_decision,
                    )

                await send(message)

            try:
                await self.app(scope, limited_receive, secured_send)
            except RequestBodyTooLarge:
                if response_started:
                    status_code = 500
                    raise

                status_code = 413
                self.metrics.record_security_event("request_body_too_large")
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="request_body_too_large",
                    message="Request body exceeds the configured limit.",
                    request_id=request_id,
                    origin=allowed_origin,
                    rate_decision=rate_decision,
                    scheme=scope.get("scheme", "http"),
                )
            except Exception:
                self.metrics.record_security_event("unhandled_exception")
                LOGGER.exception(
                    "http_request_failed",
                    extra={
                        "request_id": request_id,
                        "method": method,
                        "route": _resolved_route(scope),
                        "security_event": "unhandled_exception",
                    },
                )

                if response_started:
                    status_code = 500
                    raise

                status_code = 500
                await self._send_json_error(
                    send=send,
                    status_code=status_code,
                    code="internal_server_error",
                    message="An unexpected error occurred.",
                    request_id=request_id,
                    origin=allowed_origin,
                    rate_decision=rate_decision,
                    scheme=scope.get("scheme", "http"),
                )
        finally:
            await finish()

    @staticmethod
    def _content_length(headers: Headers) -> int:
        raw_values = headers.getlist("content-length")
        transfer_encoding = headers.get("transfer-encoding")

        if transfer_encoding is not None:
            if raw_values or transfer_encoding.strip().lower() != "chunked":
                raise InvalidContentLength

        if not raw_values:
            return 0

        if len(raw_values) != 1:
            raise InvalidContentLength

        raw_value = raw_values[0]

        try:
            value = int(raw_value)
        except ValueError as exc:
            raise InvalidContentLength from exc

        if value < 0:
            raise InvalidContentLength

        return value

    @staticmethod
    def _is_json_content_type(headers: Headers) -> bool:
        content_type = headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        return (
            media_type == "application/json"
            or media_type.endswith("+json")
        )

    def _apply_response_headers(
        self,
        *,
        headers: MutableHeaders,
        request_id: str,
        scheme: str,
        origin: str | None,
        rate_decision: RateLimitDecision | None,
    ) -> None:
        headers["X-Request-ID"] = request_id
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Cache-Control"] = "no-store"
        headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        if scheme == "https":
            headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        for name, value in _rate_headers(rate_decision).items():
            headers[name] = value

        if origin is not None:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Expose-Headers"] = (
                "X-Request-ID, RateLimit-Limit, "
                "RateLimit-Remaining, RateLimit-Reset"
            )
            headers.append("Vary", "Origin")

    async def _send_json_error(
        self,
        *,
        send: Send,
        status_code: int,
        code: str,
        message: str,
        request_id: str,
        origin: str | None = None,
        rate_decision: RateLimitDecision | None = None,
        scheme: str = "http",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(
            {
                "detail": {
                    "code": code,
                    "message": message,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        raw_headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        message: Message = {
            "type": "http.response.start",
            "status": status_code,
            "headers": raw_headers,
        }
        mutable_headers = MutableHeaders(scope=message)
        self._apply_response_headers(
            headers=mutable_headers,
            request_id=request_id,
            scheme=scheme,
            origin=origin,
            rate_decision=rate_decision,
        )

        for name, value in (extra_headers or {}).items():
            mutable_headers[name] = value

        await send(message)
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )

    async def _send_empty(
        self,
        *,
        send: Send,
        status_code: int,
        request_id: str,
        origin: str,
        scheme: str,
    ) -> None:
        message: Message = {
            "type": "http.response.start",
            "status": status_code,
            "headers": [(b"content-length", b"0")],
        }
        mutable_headers = MutableHeaders(scope=message)
        self._apply_response_headers(
            headers=mutable_headers,
            request_id=request_id,
            scheme=scheme,
            origin=origin,
            rate_decision=None,
        )
        mutable_headers["Access-Control-Allow-Methods"] = ", ".join(
            sorted(CORS_METHODS)
        )
        mutable_headers["Access-Control-Allow-Headers"] = ", ".join(
            sorted(CORS_HEADERS)
        )
        mutable_headers["Access-Control-Max-Age"] = "600"
        await send(message)
        await send({"type": "http.response.body", "body": b""})


__all__ = [
    "InvalidContentLength",
    "RequestBodyTooLarge",
    "SecurityObservabilityMiddleware",
]
