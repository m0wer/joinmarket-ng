"""
Tor control port client for creating ephemeral hidden services.

This module provides async interface to Tor's control protocol (spec v1)
for dynamically creating hidden services with cookie authentication.

Reference: https://spec.torproject.org/control-spec/index.html
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from loguru import logger


class TorControlError(Exception):
    """Base exception for Tor control errors."""

    pass


class TorAuthenticationError(TorControlError):
    """Authentication with Tor control port failed."""

    pass


class TorHiddenServiceError(TorControlError):
    """Failed to create or manage hidden service."""

    pass


class EphemeralHiddenService:
    """
    Represents an ephemeral hidden service created via Tor control port.

    Ephemeral hidden services are transient - they exist only while
    the control connection is open. When the connection closes,
    the hidden service is automatically removed.
    """

    def __init__(
        self,
        service_id: str,
        private_key: str | None = None,
        ports: list[tuple[int, str]] | None = None,
    ):
        """
        Initialize ephemeral hidden service info.

        Args:
            service_id: The .onion address without .onion suffix (56 chars for v3)
            private_key: Optional private key for recreating the service
            ports: List of (virtual_port, target) mappings
        """
        self.service_id = service_id
        self.private_key = private_key
        self.ports = ports or []

    @property
    def onion_address(self) -> str:
        """Get the full .onion address."""
        return f"{self.service_id}.onion"

    def __repr__(self) -> str:
        return f"EphemeralHiddenService({self.onion_address}, ports={self.ports})"


class TorControlClient:
    """
    Async client for Tor control protocol.

    Supports cookie authentication and ephemeral hidden service creation.
    The client maintains a persistent connection to control port.

    Example:
        async with TorControlClient() as client:
            hs = await client.create_ephemeral_hidden_service(
                ports=[(8765, "127.0.0.1:8765")]
            )
            print(f"Hidden service: {hs.onion_address}")
            # Service exists while connection is open
        # Service removed when context exits
    """

    def __init__(
        self,
        control_host: str = "127.0.0.1",
        control_port: int = 9051,
        cookie_path: str | Path | None = None,
        password: str | None = None,
    ):
        """
        Initialize Tor control client.

        Args:
            control_host: Tor control port host
            control_port: Tor control port number
            cookie_path: Path to cookie auth file (usually /var/lib/tor/control_auth_cookie)
            password: Optional password for HASHEDPASSWORD auth (not recommended)
        """
        self.control_host = control_host
        self.control_port = control_port
        self.cookie_path = Path(cookie_path) if cookie_path else None
        self.password = password

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._authenticated = False
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

        # Track created hidden services for cleanup
        self._hidden_services: list[EphemeralHiddenService] = []

    async def __aenter__(self) -> TorControlClient:
        """Async context manager entry - connect and authenticate."""
        await self.connect()
        await self.authenticate()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit - close connection."""
        await self.close()

    async def connect(self) -> None:
        """Connect to Tor control port."""
        if self._connected:
            return

        try:
            logger.debug(f"Connecting to Tor control port {self.control_host}:{self.control_port}")
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.control_host, self.control_port),
                timeout=10.0,
            )
            self._connected = True
            logger.info(f"Connected to Tor control port at {self.control_host}:{self.control_port}")
        except TimeoutError as e:
            raise TorControlError(
                f"Timeout connecting to Tor control port at {self.control_host}:{self.control_port}"
            ) from e
        except OSError as e:
            raise TorControlError(
                f"Failed to connect to Tor control port at "
                f"{self.control_host}:{self.control_port}: {e}"
            ) from e

    async def close(self) -> None:
        """Close connection to Tor control port."""
        if not self._connected:
            return

        self._connected = False
        self._authenticated = False
        self._hidden_services.clear()

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
        self._reader = None

        logger.debug("Closed Tor control connection")

    async def _send_command(self, command: str) -> None:
        """Send a command to Tor control port."""
        if not self._connected or not self._writer:
            raise TorControlError("Not connected to Tor control port")

        async with self._write_lock:
            logger.trace(f"Tor control send: {command}")
            self._writer.write(f"{command}\r\n".encode())
            await self._writer.drain()

    async def _read_response(self) -> list[tuple[str, str, str]]:
        """
        Read response from Tor control port.

        Returns:
            List of (status_code, separator, message) tuples.
            Separator is '-' for multi-line, ' ' for last/single line, '+' for data.
        """
        if not self._connected or not self._reader:
            raise TorControlError("Not connected to Tor control port")

        responses: list[tuple[str, str, str]] = []

        async with self._read_lock:
            while True:
                try:
                    line = await asyncio.wait_for(self._reader.readline(), timeout=30.0)
                except TimeoutError as e:
                    raise TorControlError("Timeout reading from Tor control port") from e

                if not line:
                    raise TorControlError("Connection closed by Tor")

                line_str = line.decode("utf-8").rstrip("\r\n")
                logger.trace(f"Tor control recv: {line_str}")

                if len(line_str) < 4:
                    raise TorControlError(f"Invalid response format: {line_str}")

                status_code = line_str[:3]
                separator = line_str[3]
                message = line_str[4:]

                responses.append((status_code, separator, message))

                # Handle multi-line data responses (status+data)
                if separator == "+":
                    # Read until we see a line with just "."
                    data_lines: list[str] = []
                    while True:
                        data_line = await self._reader.readline()
                        data_str = data_line.decode("utf-8").rstrip("\r\n")
                        if data_str == ".":
                            break
                        data_lines.append(data_str)
                    # Store data as message content
                    responses[-1] = (status_code, separator, "\n".join(data_lines))

                # Single line or last line of multi-line response
                if separator == " ":
                    break

        return responses

    async def _command(self, command: str) -> list[tuple[str, str, str]]:
        """Send command and read response."""
        await self._send_command(command)
        return await self._read_response()

    def _check_success(
        self, responses: list[tuple[str, str, str]], expected_code: str = "250"
    ) -> None:
        """Check if response indicates success."""
        if not responses:
            raise TorControlError("Empty response from Tor")

        # Check the last response (final status)
        status_code, _, message = responses[-1]
        if status_code != expected_code:
            raise TorControlError(f"Tor command failed: {status_code} {message}")

    async def authenticate(self) -> None:
        """
        Authenticate with Tor control port.

        Tries cookie authentication first if cookie_path is set,
        then falls back to password if provided.
        """
        if self._authenticated:
            return

        if not self._connected:
            await self.connect()

        # Try cookie authentication
        if self.cookie_path:
            await self._authenticate_cookie()
            return

        # Try password authentication
        if self.password:
            await self._authenticate_password()
            return

        # Try null authentication (for permissive configs)
        try:
            responses = await self._command("AUTHENTICATE")
            self._check_success(responses)
            self._authenticated = True
            logger.info("Authenticated with Tor (null auth)")
        except TorControlError as e:
            raise TorAuthenticationError(
                "No authentication method configured. Provide cookie_path or password."
            ) from e

    async def _authenticate_cookie(self) -> None:
        """Authenticate using cookie file."""
        if not self.cookie_path:
            raise TorAuthenticationError("Cookie path not configured")

        try:
            cookie_data = self.cookie_path.read_bytes()
            cookie_hex = cookie_data.hex()
        except FileNotFoundError as e:
            raise TorAuthenticationError(f"Cookie file not found: {self.cookie_path}") from e
        except PermissionError as e:
            raise TorAuthenticationError(
                f"Permission denied reading cookie file: {self.cookie_path}"
            ) from e

        try:
            responses = await self._command(f"AUTHENTICATE {cookie_hex}")
            self._check_success(responses)
            self._authenticated = True
            logger.info("Authenticated with Tor using cookie")
        except TorControlError as e:
            raise TorAuthenticationError(f"Cookie authentication failed: {e}") from e

    async def _authenticate_password(self) -> None:
        """Authenticate using password."""
        if not self.password:
            raise TorAuthenticationError("Password not configured")

        # Quote the password properly
        escaped_password = self.password.replace("\\", "\\\\").replace('"', '\\"')

        try:
            responses = await self._command(f'AUTHENTICATE "{escaped_password}"')
            self._check_success(responses)
            self._authenticated = True
            logger.info("Authenticated with Tor using password")
        except TorControlError as e:
            raise TorAuthenticationError(f"Password authentication failed: {e}") from e

    async def get_info(self, key: str) -> str:
        """
        Get information from Tor.

        Args:
            key: Information key (e.g., "version", "config-file")

        Returns:
            The requested information value
        """
        if not self._authenticated:
            raise TorControlError("Not authenticated")

        responses = await self._command(f"GETINFO {key}")
        self._check_success(responses)

        # Parse key=value from first response
        for status, _, message in responses:
            if status == "250" and "=" in message:
                _, value = message.split("=", 1)
                return value

        raise TorControlError(f"Could not parse GETINFO response for {key}")

    async def create_ephemeral_hidden_service(
        self,
        ports: list[tuple[int, str]],
        key_type: str = "NEW",
        key_blob: str = "ED25519-V3",
        discard_pk: bool = False,
        detach: bool = False,
        await_publication: bool = False,
        max_streams: int | None = None,
    ) -> EphemeralHiddenService:
        """
        Create an ephemeral hidden service using ADD_ONION.

        Ephemeral services exist only while the control connection is open.
        When the connection closes, the hidden service is automatically removed.

        Args:
            ports: List of (virtual_port, target) tuples.
                   Target is "host:port" or just "port" for localhost.
            key_type: "NEW" for new key, "ED25519-V3" or "RSA1024" for existing key
            key_blob: For NEW: "ED25519-V3" (recommended) or "RSA1024"
                      For existing: base64-encoded private key
            discard_pk: If True, don't return the private key
            detach: If True, service persists after control connection closes
            await_publication: If True, wait for HS descriptor to be published
            max_streams: Maximum concurrent streams (None for unlimited)

        Returns:
            EphemeralHiddenService with the created service details

        Example:
            # Create service that forwards port 80 to local 8080
            hs = await client.create_ephemeral_hidden_service(
                ports=[(80, "127.0.0.1:8080")]
            )
        """
        if not self._authenticated:
            raise TorControlError("Not authenticated")

        # Build port specifications
        port_specs = []
        for virtual_port, target in ports:
            port_specs.append(f"Port={virtual_port},{target}")

        # Build flags
        flags = []
        if discard_pk:
            flags.append("DiscardPK")
        if detach:
            flags.append("Detach")
        if await_publication:
            flags.append("AwaitPublication")

        # Build command
        cmd_parts = [f"ADD_ONION {key_type}:{key_blob}"]
        cmd_parts.extend(port_specs)

        if flags:
            cmd_parts.append(f"Flags={','.join(flags)}")

        if max_streams is not None:
            cmd_parts.append(f"MaxStreams={max_streams}")

        command = " ".join(cmd_parts)

        try:
            responses = await self._command(command)
            self._check_success(responses)
        except TorControlError as e:
            raise TorHiddenServiceError(f"Failed to create hidden service: {e}") from e

        # Parse response to get service ID and optional private key
        service_id: str | None = None
        private_key: str | None = None

        for status, _, message in responses:
            if status == "250":
                if message.startswith("ServiceID="):
                    service_id = message.split("=", 1)[1]
                elif message.startswith("PrivateKey="):
                    private_key = message.split("=", 1)[1]

        if not service_id:
            raise TorHiddenServiceError("No ServiceID in ADD_ONION response")

        hs = EphemeralHiddenService(
            service_id=service_id,
            private_key=private_key,
            ports=list(ports),
        )

        if not detach:
            self._hidden_services.append(hs)

        logger.info(f"Created ephemeral hidden service: {hs.onion_address}")
        return hs

    async def delete_ephemeral_hidden_service(self, service_id: str) -> None:
        """
        Delete an ephemeral hidden service.

        Args:
            service_id: The service ID (without .onion suffix)
        """
        if not self._authenticated:
            raise TorControlError("Not authenticated")

        # Strip .onion if included
        if service_id.endswith(".onion"):
            service_id = service_id[:-6]

        try:
            responses = await self._command(f"DEL_ONION {service_id}")
            self._check_success(responses)
            logger.info(f"Deleted hidden service: {service_id}")
        except TorControlError as e:
            raise TorHiddenServiceError(f"Failed to delete hidden service: {e}") from e

        # Remove from tracking
        self._hidden_services = [hs for hs in self._hidden_services if hs.service_id != service_id]

    async def get_version(self) -> str:
        """Get Tor version string."""
        return await self.get_info("version")

    @property
    def is_connected(self) -> bool:
        """Check if connected to control port."""
        return self._connected

    @property
    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._authenticated

    @property
    def hidden_services(self) -> list[EphemeralHiddenService]:
        """Get list of active ephemeral hidden services created by this client."""
        return list(self._hidden_services)
