"""Language model adapter interface, the hosted adapter and the factory that builds it from configuration."""

from agentvax.llm.factory import UnsupportedProvider, build

__all__ = ["UnsupportedProvider", "build"]
