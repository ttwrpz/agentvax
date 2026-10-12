"""Federated detector: three wallets train locally, clip and mask their updates, and an aggregator averages them.

Each wallet canary-checks the candidate before adopting it. The aggregator anchors the adopted model's
``(version, hash)`` in the ThreatBulletin. ``run`` is the offline experiment that writes ``results/federation.json``.
"""
