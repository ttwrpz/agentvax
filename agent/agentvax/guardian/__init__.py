"""The guardian: a separate process that holds the guardian key, scores raw untrusted content and signs the
EIP-712 attestation.

``service`` runs in that process and is the only module that reads the key. ``client`` talks to it and
``protocol`` is the line protocol between them. The planner, reader and mission modules import none of these.
"""
