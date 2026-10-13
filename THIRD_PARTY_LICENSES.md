# Third-party licences

AgentVax builds on the third-party software listed here. The Solidity libraries were read from their vendored package files in `contracts/lib/`, and the Python packages were read from the metadata of the installed project environment. The licence of AgentVax itself is in the `LICENSE` file.

## Solidity libraries

Both libraries are vendored in `contracts/lib/` with their licence files.

| Name | Version | Licence |
| --- | --- | --- |
| OpenZeppelin Contracts | 5.1.0 | MIT |
| forge-std | 1.17.0 | Apache-2.0 OR MIT |

## Python packages: direct dependencies

These are the direct dependencies declared in `agent/pyproject.toml`. pytest is an optional development dependency.

| Name | Version | Licence |
| --- | --- | --- |
| pydantic | 2.14.0 | MIT |
| web3 | 8.0.0 | MIT |
| eth-account | 0.14.0 | MIT |
| fastapi | 0.138.2 | MIT |
| uvicorn | 0.49.0 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| flwr | 1.39.0 | Apache-2.0 |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| eth-keys | 0.8.0 | MIT |
| eth_abi | 6.0.0 | MIT |
| eth-utils | 6.0.0 | MIT License |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause |
| pytest | 9.1.1 | MIT |

## Python packages: other installed packages

These are the remaining packages installed in the project environment, including dependencies of the packages above and the build tools.

| Name | Version | Licence |
| --- | --- | --- |
| Mako | 1.4.3 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| SQLAlchemy | 2.1.4 | MIT |
| aiohappyeyeballs | 2.7.1 | PSF-2.0 |
| aiohttp | 3.14.5 | Apache-2.0 AND MIT |
| aiosignal | 1.4.0 | Apache 2.0 |
| alembic | 1.20.0 | MIT |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| attrs | 26.1.0 | MIT |
| bitarray | 3.12.0 | PSF-2.0 |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| ckzg | 2.1.8 | Apache-2.0 |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD License |
| cytoolz | 1.2.0 | BSD-3-Clause |
| eth-hash | 0.8.0 | MIT License |
| eth-keyfile | 0.10.0 | MIT |
| eth-rlp | 3.0.0 | MIT |
| eth-typing | 6.0.0 | MIT License |
| frozenlist | 1.8.0 | Apache-2.0 |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| grpcio | 1.84.0 | Apache-2.0 |
| grpcio-health-checking | 1.81.1 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| hexbytes | 2.0.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httptools | 0.9.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| iniconfig | 2.3.1 | MIT |
| iterators | 0.0.2 | MIT License |
| markdown-it-py | 4.2.0 | MIT License |
| mdurl | 0.1.2 | MIT License |
| multidict | 7.1.0 | Apache-2.0 |
| packaging | 25.0 | Apache Software License, BSD License |
| parsimonious | 0.10.0 | MIT |
| pathspec | 1.1.1 | Mozilla Public License 2.0 (MPL 2.0) |
| pluggy | 1.6.0 | MIT |
| prompt_toolkit | 3.0.53 | BSD License |
| propcache | 0.5.4 | Apache-2.0 |
| protobuf | 6.33.6 | 3-Clause BSD License |
| py-ecc | 8.0.0 | MIT |
| pycparser | 3.11 | BSD-3-Clause |
| pycryptodome | 3.24.0 | BSD, Public Domain |
| pydantic_core | 2.50.0 | MIT |
| pyunormalize | 18.0.0 | MIT |
| pywin32 | 312 | PSF |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python |
| requests | 2.34.2 | Apache-2.0 |
| rich | 14.3.4 | MIT |
| rlp | 5.0.0 | MIT |
| shellingham | 1.5.4 | ISC License |
| starlette | 1.3.1 | BSD-3-Clause |
| tomli | 2.5.0 | MIT |
| tomli_w | 1.2.0 | MIT License |
| toolz | 1.2.0 | BSD-3-Clause |
| typer | 0.20.1 | MIT |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| urllib3 | 2.8.0 | MIT |
| uv | 0.11.33 | MIT OR Apache-2.0 |
| watchfiles | 1.3.0 | MIT |
| wcwidth | 0.9.2 | MIT License |
| websockets | 17.2 | BSD-3-Clause |
| yarl | 1.25.1 | Apache-2.0 |

## Tools used but not distributed

AgentVax uses these tools to build, test and deploy, but does not ship them. The version is the one installed on the build machine. The licence is the statement published by the Foundry project.

| Name | Version | Licence |
| --- | --- | --- |
| Foundry (forge, anvil, cast) | 1.5.1-stable | Apache-2.0 OR MIT |
