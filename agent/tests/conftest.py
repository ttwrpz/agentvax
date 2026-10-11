"""Shared pytest fixtures for the agentvax tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from chain_support import AnvilNode, artifact_store, start_anvil

from agentvax.chain.artifacts import ArtifactStore


@pytest.fixture(scope="session")
def artifacts() -> ArtifactStore:
    """Foundry artifacts, built once if missing or stale."""
    return artifact_store()


@pytest.fixture(scope="session")
def anvil_factory() -> Iterator[list[AnvilNode]]:
    """Every Anvil started through ``start_node`` is stopped at the end of the session, whatever happens."""
    nodes: list[AnvilNode] = []
    try:
        yield nodes
    finally:
        for node in nodes:
            node.stop()


@pytest.fixture(scope="session")
def start_node(anvil_factory: list[AnvilNode]):  # type: ignore[no-untyped-def]
    def start(chain_id: int) -> AnvilNode:
        node = start_anvil(chain_id)
        anvil_factory.append(node)
        return node

    return start


@pytest.fixture(scope="session")
def anvil(start_node) -> AnvilNode:  # type: ignore[no-untyped-def]
    """One local Anvil with chain id 31337 for the session."""
    return start_node(31337)
