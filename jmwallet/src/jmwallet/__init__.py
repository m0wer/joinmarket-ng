"""
JoinMarket wallet library with pluggable blockchain backends.
"""

from jmcore.version import __version__

from jmwallet.backends.base import BlockchainBackend
from jmwallet.wallet.service import WalletService

__all__ = ["BlockchainBackend", "WalletService", "__version__"]
