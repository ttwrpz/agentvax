"""Scaffold check that the agentvax package imports."""

import agentvax


def test_package_imports() -> None:
    assert agentvax.__version__ == "0.1.0"
