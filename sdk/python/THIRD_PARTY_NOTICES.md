# DecAustrum Python SDK third-party notices

The DecAustrum Portfolio Evaluation License applies only to original DecAustrum
SDK materials. The SDK declares HTTPX as an external dependency and does not
bundle HTTPX or its dependency code in the DecAustrum wheel.

The following dependency versions were audited in the DecAustrum 0.1.0
development and integration environment. Package installers may select later
compatible versions within the SDK's declared dependency range. Every installed
package remains subject to its own license, and the license files distributed
inside each package are authoritative.

| Package | Audited version | License | Upstream |
| --- | ---: | --- | --- |
| `httpx` | 0.28.1 | BSD-3-Clause | [encode/httpx](https://github.com/encode/httpx) |
| `httpcore` | 1.0.9 | BSD-3-Clause | [encode/httpcore](https://github.com/encode/httpcore) |
| `anyio` | 4.14.2 | MIT | [agronholm/anyio](https://github.com/agronholm/anyio) |
| `certifi` | 2026.7.22 | MPL-2.0 | [certifi/python-certifi](https://github.com/certifi/python-certifi) |
| `h11` | 0.16.0 | MIT | [python-hyper/h11](https://github.com/python-hyper/h11) |
| `idna` | 3.18 | BSD-3-Clause | [kjd/idna](https://github.com/kjd/idna) |
| `typing-extensions` | 4.16.0 | PSF-2.0 | [python/typing_extensions](https://github.com/python/typing_extensions) |

Setuptools is used as MIT-licensed build tooling and is not bundled as SDK
runtime code.
