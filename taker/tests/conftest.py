"""
Test configuration for taker tests.
"""

from __future__ import annotations

import pytest
from _taker_test_helpers import SAMPLE_MNEMONIC


@pytest.fixture
def sample_mnemonic() -> str:
    """Test mnemonic (not for production use!)."""
    return SAMPLE_MNEMONIC
