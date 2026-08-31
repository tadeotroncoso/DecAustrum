# Third-party notices

DecAustrum's Portfolio Evaluation License applies only to original DecAustrum
materials. Dependencies, the Python runtime, container base-image components,
and other third-party materials remain subject to their own licenses.

The following table records the Python runtime and SDK transport packages
audited for DecAustrum 0.1.0. Package distributions retain their original license
files under their installed `.dist-info/licenses` directories. The links below
identify the upstream projects; upstream license files are authoritative.

| Package | Audited version | License | Upstream |
| --- | ---: | --- | --- |
| `annotated-doc` | 0.0.5 | MIT | [fastapi/annotated-doc](https://github.com/fastapi/annotated-doc) |
| `annotated-types` | 0.8.0 | MIT | [annotated-types/annotated-types](https://github.com/annotated-types/annotated-types) |
| `anyio` | 4.14.2 | MIT | [agronholm/anyio](https://github.com/agronholm/anyio) |
| `click` | 8.4.2 | BSD-3-Clause | [pallets/click](https://github.com/pallets/click) |
| `colorama` | 0.4.6 | BSD-3-Clause | [tartley/colorama](https://github.com/tartley/colorama) |
| `fastapi` | 0.141.1 | MIT | [fastapi/fastapi](https://github.com/fastapi/fastapi) |
| `h11` | 0.16.0 | MIT | [python-hyper/h11](https://github.com/python-hyper/h11) |
| `idna` | 3.18 | BSD-3-Clause | [kjd/idna](https://github.com/kjd/idna) |
| `pydantic` | 2.13.4 | MIT | [pydantic/pydantic](https://github.com/pydantic/pydantic) |
| `pydantic-core` | 2.46.4 | MIT | [pydantic/pydantic-core](https://github.com/pydantic/pydantic-core) |
| `python-dotenv` | 1.2.2 | BSD-3-Clause | [theskumar/python-dotenv](https://github.com/theskumar/python-dotenv) |
| `PyYAML` | 6.0.3 | MIT | [yaml/pyyaml](https://github.com/yaml/pyyaml) |
| `starlette` | 1.6.0 | BSD-3-Clause | [Kludex/starlette](https://github.com/Kludex/starlette) |
| `typing-extensions` | 4.16.0 | PSF-2.0 | [python/typing_extensions](https://github.com/python/typing_extensions) |
| `typing-inspection` | 0.4.2 | MIT | [pydantic/typing-inspection](https://github.com/pydantic/typing-inspection) |
| `uvicorn` | 0.52.1 | BSD-3-Clause | [Kludex/uvicorn](https://github.com/Kludex/uvicorn) |
| `httpx` | 0.28.1 | BSD-3-Clause | [encode/httpx](https://github.com/encode/httpx) |
| `httpcore` | 1.0.9 | BSD-3-Clause | [encode/httpcore](https://github.com/encode/httpcore) |
| `certifi` | 2026.7.22 | MPL-2.0 | [certifi/python-certifi](https://github.com/certifi/python-certifi) |

The SDK declares HTTPX as an external dependency and does not bundle HTTPX or
its dependency code in the DecAustrum wheel. The backend container installs the
pinned Python package distributions without removing their license metadata.

The SDK and backend use Setuptools 84.0.0 (MIT) as build tooling. Build and
development tools are not part of the DecAustrum runtime merely because they are
listed in the development lock file.

The runtime container derives from the pinned official
`python:3.12.14-slim-bookworm` image. Python, Debian, certificate material, and
operating-system packages in that image retain their own notices and license
files; the DecAustrum license does not replace them.
