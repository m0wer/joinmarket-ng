"""
Tests for Tor control port functionality.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from jmcore.tor_control import (
    EphemeralHiddenService,
    TorAuthenticationError,
    TorControlClient,
    TorControlError,
    TorHiddenServiceError,
)


class TestEphemeralHiddenService:
    """Tests for EphemeralHiddenService data class."""

    def test_onion_address(self) -> None:
        """Test onion_address property."""
        service_id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv"
        hs = EphemeralHiddenService(service_id=service_id)

        assert hs.onion_address == f"{service_id}.onion"

    def test_with_ports_and_key(self) -> None:
        """Test with ports and private key."""
        service_id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv"
        private_key = "ED25519-V3:base64encodedkey=="
        ports = [(80, "127.0.0.1:8080"), (443, "127.0.0.1:8443")]

        hs = EphemeralHiddenService(
            service_id=service_id,
            private_key=private_key,
            ports=ports,
        )

        assert hs.service_id == service_id
        assert hs.private_key == private_key
        assert hs.ports == ports

    def test_repr(self) -> None:
        """Test string representation."""
        service_id = "abcdef"
        hs = EphemeralHiddenService(service_id=service_id, ports=[(80, "localhost:8080")])

        assert "abcdef.onion" in repr(hs)
        assert "80" in repr(hs)


class TestTorControlClient:
    """Tests for TorControlClient."""

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful connection to control port."""
        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(control_host="127.0.0.1", control_port=9051)

            await client.connect()

            assert client.is_connected
            mock_open.assert_called_once()

            await client.close()

    @pytest.mark.asyncio
    async def test_connect_timeout(self) -> None:
        """Test connection timeout handling."""
        with patch("asyncio.open_connection", side_effect=TimeoutError):
            client = TorControlClient(control_host="127.0.0.1", control_port=9051)

            with pytest.raises(TorControlError, match="Timeout"):
                await client.connect()

            assert not client.is_connected

    @pytest.mark.asyncio
    async def test_connect_refused(self) -> None:
        """Test connection refused handling."""
        with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
            client = TorControlClient(control_host="127.0.0.1", control_port=9051)

            with pytest.raises(TorControlError, match="Failed to connect"):
                await client.connect()

            assert not client.is_connected

    @pytest.mark.asyncio
    async def test_authenticate_cookie_success(self, tmp_path: Path) -> None:
        """Test successful cookie authentication."""
        # Create a mock cookie file
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_data = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 4  # 32 bytes
        cookie_path.write_bytes(cookie_data)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            # Simulate successful auth response
            mock_reader.readline = AsyncMock(return_value=b"250 OK\r\n")
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()
            await client.authenticate()

            assert client.is_authenticated

            # Verify AUTHENTICATE command was sent with cookie hex
            calls = mock_writer.write.call_args_list
            assert any(b"AUTHENTICATE" in call[0][0] for call in calls)

            await client.close()

    @pytest.mark.asyncio
    async def test_authenticate_cookie_not_found(self) -> None:
        """Test cookie authentication with missing file."""
        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=Path("/nonexistent/cookie"),
            )

            await client.connect()

            with pytest.raises(TorAuthenticationError, match="not found"):
                await client.authenticate()

            await client.close()

    @pytest.mark.asyncio
    async def test_authenticate_password_success(self) -> None:
        """Test successful password authentication."""
        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            # Simulate successful auth response
            mock_reader.readline = AsyncMock(return_value=b"250 OK\r\n")
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                password="mysecretpassword",
            )

            await client.connect()
            await client.authenticate()

            assert client.is_authenticated

            # Verify password was sent
            calls = mock_writer.write.call_args_list
            assert any(b"mysecretpassword" in call[0][0] for call in calls)

            await client.close()

    @pytest.mark.asyncio
    async def test_authenticate_failure(self, tmp_path: Path) -> None:
        """Test authentication failure handling."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"badcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            # Simulate auth failure
            mock_reader.readline = AsyncMock(return_value=b"515 Bad authentication\r\n")
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()

            with pytest.raises(TorAuthenticationError, match="failed"):
                await client.authenticate()

            await client.close()

    @pytest.mark.asyncio
    async def test_create_hidden_service_success(self, tmp_path: Path) -> None:
        """Test successful ephemeral hidden service creation."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"validcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            # Response sequence: auth OK, then ADD_ONION response
            service_id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv"
            responses = [
                b"250 OK\r\n",  # AUTHENTICATE
                b"250-ServiceID=" + service_id.encode() + b"\r\n",  # ADD_ONION
                b"250 OK\r\n",  # ADD_ONION final
            ]
            mock_reader.readline = AsyncMock(side_effect=responses)
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()
            await client.authenticate()

            hs = await client.create_ephemeral_hidden_service(ports=[(27183, "127.0.0.1:27183")])

            assert hs.service_id == service_id
            assert hs.onion_address == f"{service_id}.onion"
            assert len(client.hidden_services) == 1

            await client.close()

    @pytest.mark.asyncio
    async def test_create_hidden_service_failure(self, tmp_path: Path) -> None:
        """Test hidden service creation failure."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"validcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            responses = [
                b"250 OK\r\n",  # AUTHENTICATE
                b"512 Invalid port\r\n",  # ADD_ONION error
            ]
            mock_reader.readline = AsyncMock(side_effect=responses)
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()
            await client.authenticate()

            with pytest.raises(TorHiddenServiceError, match="Failed"):
                await client.create_ephemeral_hidden_service(ports=[(27183, "127.0.0.1:27183")])

            await client.close()

    @pytest.mark.asyncio
    async def test_get_info(self, tmp_path: Path) -> None:
        """Test GETINFO command."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"validcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            responses = [
                b"250 OK\r\n",  # AUTHENTICATE
                b"250-version=0.4.7.10\r\n",  # GETINFO
                b"250 OK\r\n",
            ]
            mock_reader.readline = AsyncMock(side_effect=responses)
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()
            await client.authenticate()

            version = await client.get_version()
            assert version == "0.4.7.10"

            await client.close()

    @pytest.mark.asyncio
    async def test_context_manager(self, tmp_path: Path) -> None:
        """Test async context manager."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"validcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            mock_reader.readline = AsyncMock(return_value=b"250 OK\r\n")
            mock_open.return_value = (mock_reader, mock_writer)

            async with TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            ) as client:
                assert client.is_connected
                assert client.is_authenticated

            # After context exit, should be closed
            assert not client.is_connected

    @pytest.mark.asyncio
    async def test_delete_hidden_service(self, tmp_path: Path) -> None:
        """Test DEL_ONION command."""
        cookie_path = tmp_path / "control_auth_cookie"
        cookie_path.write_bytes(b"validcookie" * 4)

        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            service_id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv"
            responses = [
                b"250 OK\r\n",  # AUTHENTICATE
                b"250-ServiceID=" + service_id.encode() + b"\r\n",  # ADD_ONION
                b"250 OK\r\n",  # ADD_ONION final
                b"250 OK\r\n",  # DEL_ONION
            ]
            mock_reader.readline = AsyncMock(side_effect=responses)
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(
                control_host="127.0.0.1",
                control_port=9051,
                cookie_path=cookie_path,
            )

            await client.connect()
            await client.authenticate()

            hs = await client.create_ephemeral_hidden_service(ports=[(27183, "127.0.0.1:27183")])
            assert len(client.hidden_services) == 1

            await client.delete_ephemeral_hidden_service(hs.service_id)
            assert len(client.hidden_services) == 0

            await client.close()

    @pytest.mark.asyncio
    async def test_command_not_authenticated(self) -> None:
        """Test commands fail when not authenticated."""
        with patch("asyncio.open_connection") as mock_open:
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_open.return_value = (mock_reader, mock_writer)

            client = TorControlClient(control_host="127.0.0.1", control_port=9051)

            await client.connect()
            # Don't authenticate

            with pytest.raises(TorControlError, match="Not authenticated"):
                await client.get_info("version")

            with pytest.raises(TorControlError, match="Not authenticated"):
                await client.create_ephemeral_hidden_service(ports=[(80, "localhost:80")])

            await client.close()
