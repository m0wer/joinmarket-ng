"""
Blockchain backend implementations.

Available backends:
- BitcoinCoreBackend: Full node via Bitcoin Core RPC (no wallet, uses scantxoutset)
- NeutrinoBackend: Lightweight BIP157/BIP158 SPV client
- MempoolBackend: Mempool.space API (third-party, no setup required)
"""

from jmwallet.backends.base import BlockchainBackend
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig

__all__ = [
    "BlockchainBackend",
    "BitcoinCoreBackend",
    "NeutrinoBackend",
    "NeutrinoConfig",
]
