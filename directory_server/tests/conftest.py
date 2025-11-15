"""
Pytest configuration and fixtures for directory server tests.
"""

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"
