import logging
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit


class RuntimeConfigurationError(RuntimeError):
    """Raised when DecAustrum runtime hardening is misconfigured."""


def _parse_bool(
    environment: Mapping[str, str],
    name: str,
    default: bool,
) -> bool:
    raw_value = environment.get(name)

    if raw_value is None:
        return default

    normalized = raw_value.strip().lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    raise RuntimeConfigurationError(
        f"{name} must be a boolean value."
    )


def _parse_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = environment.get(name)

    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeConfigurationError(
            f"{name} must be an integer."
        ) from exc

    if value < minimum or value > maximum:
        raise RuntimeConfigurationError(
            f"{name} must be between {minimum} and {maximum}."
        )

    return value


def _parse_csv(
    environment: Mapping[str, str],
    name: str,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    raw_value = environment.get(name)

    if raw_value is None:
        return default

    values = tuple(
        item.strip()
        for item in raw_value.split(",")
        if item.strip()
    )

    return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class RuntimeSettings:
    environment: str = "development"
    trusted_hosts: tuple[str, ...] = (
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
    )
    cors_allowed_origins: tuple[str, ...] = ()
    enforce_https: bool = False
    expose_docs: bool = True
    rate_limit_enabled: bool = True
    max_request_body_bytes: int = 1_048_576
    rate_limit_window_seconds: int = 60
    authorization_rate_limit: int = 300
    tenant_rate_limit: int = 600
    admin_rate_limit: int = 300
    approval_ttl_seconds: int = 86_400
    execution_grant_ttl_seconds: int = 300
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "RuntimeSettings":
        values = environment if environment is not None else os.environ
        runtime_environment = values.get(
            "DECAUSTRUM_ENVIRONMENT",
            "development",
        ).strip().lower()
        default_hosts = (
            ()
            if runtime_environment == "production"
            else (
                "localhost",
                "127.0.0.1",
                "::1",
                "testserver",
            )
        )

        return cls(
            environment=runtime_environment,
            trusted_hosts=_parse_csv(
                values,
                "DECAUSTRUM_TRUSTED_HOSTS",
                default_hosts,
            ),
            cors_allowed_origins=_parse_csv(
                values,
                "DECAUSTRUM_CORS_ALLOWED_ORIGINS",
                (),
            ),
            enforce_https=_parse_bool(
                values,
                "DECAUSTRUM_ENFORCE_HTTPS",
                runtime_environment == "production",
            ),
            expose_docs=_parse_bool(
                values,
                "DECAUSTRUM_EXPOSE_DOCS",
                runtime_environment != "production",
            ),
            rate_limit_enabled=_parse_bool(
                values,
                "DECAUSTRUM_RATE_LIMIT_ENABLED",
                True,
            ),
            max_request_body_bytes=_parse_int(
                values,
                "DECAUSTRUM_MAX_REQUEST_BODY_BYTES",
                1_048_576,
                minimum=1,
                maximum=100 * 1024 * 1024,
            ),
            rate_limit_window_seconds=_parse_int(
                values,
                "DECAUSTRUM_RATE_LIMIT_WINDOW_SECONDS",
                60,
                minimum=1,
                maximum=3_600,
            ),
            authorization_rate_limit=_parse_int(
                values,
                "DECAUSTRUM_AUTHORIZATION_RATE_LIMIT",
                300,
                minimum=1,
                maximum=1_000_000,
            ),
            tenant_rate_limit=_parse_int(
                values,
                "DECAUSTRUM_TENANT_RATE_LIMIT",
                600,
                minimum=1,
                maximum=1_000_000,
            ),
            admin_rate_limit=_parse_int(
                values,
                "DECAUSTRUM_ADMIN_RATE_LIMIT",
                300,
                minimum=1,
                maximum=1_000_000,
            ),
            approval_ttl_seconds=_parse_int(
                values,
                "DECAUSTRUM_APPROVAL_TTL_SECONDS",
                86_400,
                minimum=60,
                maximum=2_592_000,
            ),
            execution_grant_ttl_seconds=_parse_int(
                values,
                "DECAUSTRUM_EXECUTION_GRANT_TTL_SECONDS",
                300,
                minimum=30,
                maximum=3_600,
            ),
            log_level=values.get(
                "DECAUSTRUM_LOG_LEVEL",
                "INFO",
            ).strip().upper(),
        )

    def validate(self) -> None:
        if self.environment not in {
            "development",
            "test",
            "production",
        }:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_ENVIRONMENT must be development, test, "
                "or production."
            )

        if not self.trusted_hosts:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_TRUSTED_HOSTS must contain at least one host."
            )

        for host in self.trusted_hosts:
            if (
                not host
                or host == "*"
                or "/" in host
                or " " in host
                or host == "*."
                or (
                    "*" in host
                    and not host.startswith("*.")
                )
            ):
                raise RuntimeConfigurationError(
                    f"Invalid trusted host pattern: {host!r}."
                )

        for origin in self.cors_allowed_origins:
            self._validate_origin(origin)

        if self.environment == "production" and not self.enforce_https:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_ENFORCE_HTTPS must be enabled in production."
            )

        if not 1 <= self.max_request_body_bytes <= 100 * 1024 * 1024:
            raise RuntimeConfigurationError(
                "Maximum request body size must be between 1 byte "
                "and 100 MiB."
            )

        for name, value, maximum in (
            (
                "rate_limit_window_seconds",
                self.rate_limit_window_seconds,
                3_600,
            ),
            (
                "authorization_rate_limit",
                self.authorization_rate_limit,
                1_000_000,
            ),
            (
                "tenant_rate_limit",
                self.tenant_rate_limit,
                1_000_000,
            ),
            (
                "admin_rate_limit",
                self.admin_rate_limit,
                1_000_000,
            ),
            (
                "approval_ttl_seconds",
                self.approval_ttl_seconds,
                2_592_000,
            ),
            (
                "execution_grant_ttl_seconds",
                self.execution_grant_ttl_seconds,
                3_600,
            ),
        ):
            if value < 1 or value > maximum:
                raise RuntimeConfigurationError(
                    f"{name} must be between 1 and {maximum}."
                )

        if not 60 <= self.approval_ttl_seconds <= 2_592_000:
            raise RuntimeConfigurationError(
                "approval_ttl_seconds must be between 60 and 2592000."
            )

        if not 30 <= self.execution_grant_ttl_seconds <= 3_600:
            raise RuntimeConfigurationError(
                "execution_grant_ttl_seconds must be between 30 and 3600."
            )

        if self.log_level not in logging.getLevelNamesMapping():
            raise RuntimeConfigurationError(
                "DECAUSTRUM_LOG_LEVEL is not a valid logging level."
            )

    def _validate_origin(self, origin: str) -> None:
        if origin == "*":
            raise RuntimeConfigurationError(
                "Wildcard CORS origins are not allowed with API keys."
            )

        parsed = urlsplit(origin)

        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeConfigurationError(
                f"Invalid CORS origin: {origin!r}."
            )

        if parsed.scheme == "http" and not (
            self.environment != "production"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise RuntimeConfigurationError(
                "CORS origins must use HTTPS except for local development."
            )

    def validate_secrets(
        self,
        *,
        project_api_key: str,
        admin_api_key: str | None,
        execution_grant_secret: str | None = None,
    ) -> None:
        if self.environment != "production":
            return

        if len(project_api_key.encode("utf-8")) < 32:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_API_KEY must contain at least 32 bytes in "
                "production."
            )

        if admin_api_key is None:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_ADMIN_API_KEY must be configured in production."
            )

        if len(admin_api_key.encode("utf-8")) < 32:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_ADMIN_API_KEY must contain at least 32 bytes "
                "in production."
            )

        if secrets.compare_digest(project_api_key, admin_api_key):
            raise RuntimeConfigurationError(
                "Project and administrator API keys must be different."
            )

        if execution_grant_secret is None:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_EXECUTION_GRANT_SECRET must be configured "
                "in production."
            )

        if len(execution_grant_secret.encode("utf-8")) < 32:
            raise RuntimeConfigurationError(
                "DECAUSTRUM_EXECUTION_GRANT_SECRET must contain at "
                "least 32 bytes in production."
            )

        if secrets.compare_digest(
            execution_grant_secret,
            project_api_key,
        ) or secrets.compare_digest(
            execution_grant_secret,
            admin_api_key,
        ):
            raise RuntimeConfigurationError(
                "Execution grant, project, and administrator secrets "
                "must be different."
            )


__all__ = [
    "RuntimeConfigurationError",
    "RuntimeSettings",
]
