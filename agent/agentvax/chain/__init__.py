"""Chain access: web3 client, Foundry artifacts, deployer, and owner and agent actions.

Every transaction goes through ``ChainClient``, which refuses chain ids outside ``ALLOWED_CHAIN_IDS``.
"""
