"""
JoinMarket Yield Generator (Maker Bot).
"""

from jmcore.version import __version__

from maker.bot import MakerBot
from maker.config import MakerConfig

__all__ = ["MakerBot", "MakerConfig", "__version__"]
