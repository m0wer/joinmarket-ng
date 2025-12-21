"""
Handshake protocol handler for peer authentication and validation.

Implements Single Responsibility Principle: only handles handshakes.
"""

import json

from jmcore.models import NetworkType, PeerInfo, PeerStatus
from jmcore.protocol import (
    JM_VERSION,
    JM_VERSION_MIN,
    NOT_SERVING_ONION_HOSTNAME,
    create_handshake_response,
    peer_supports_neutrino_compat,
)
from loguru import logger


class HandshakeError(Exception):
    pass


class HandshakeHandler:
    def __init__(
        self, network: NetworkType, server_nick: str, motd: str, neutrino_compat: bool = False
    ):
        self.network = network
        self.server_nick = server_nick
        self.motd = motd
        self.neutrino_compat = neutrino_compat

    def process_handshake(self, handshake_data: str, peer_location: str) -> tuple[PeerInfo, dict]:
        try:
            hs = json.loads(handshake_data)

            app_name = hs.get("app-name")
            is_directory = hs.get("directory", False)
            proto_ver = hs.get("proto-ver")
            features = hs.get("features", {})
            location_string = hs.get("location-string")
            nick = hs.get("nick")
            network_str = hs.get("network")

            if not all([app_name, proto_ver, nick, network_str]):
                raise HandshakeError("Missing required handshake fields")

            if app_name.lower() != "joinmarket":
                raise HandshakeError(f"Invalid app name: {app_name}")

            if is_directory:
                raise HandshakeError("Directory nodes not accepted as clients")

            if not (JM_VERSION_MIN <= proto_ver <= JM_VERSION):
                raise HandshakeError(
                    f"Protocol version {proto_ver} not in supported range [{JM_VERSION_MIN}, {JM_VERSION}]"
                )

            peer_network = self._parse_network(network_str)
            if peer_network != self.network:
                raise HandshakeError(f"Network mismatch: {network_str} != {self.network.value}")

            onion_address, port = self._parse_location(location_string)

            # Determine negotiated version (highest both support)
            negotiated_version = min(proto_ver, JM_VERSION)

            # Check if peer supports Neutrino-compatible UTXO metadata
            peer_neutrino_compat = peer_supports_neutrino_compat(hs)

            peer_info = PeerInfo(
                nick=nick,
                onion_address=onion_address,
                port=port,
                status=PeerStatus.CONNECTED,
                is_directory=False,
                network=peer_network,
                features=features,
                protocol_version=negotiated_version,
                neutrino_compat=peer_neutrino_compat,
            )

            response = create_handshake_response(
                nick=self.server_nick,
                network=self.network.value,
                accepted=True,
                motd=self.motd,
                neutrino_compat=self.neutrino_compat,
            )

            logger.info(
                f"Handshake accepted: {nick} from {peer_network.value} "
                f"at {peer_info.location_string} "
                f"(v{negotiated_version}, neutrino={peer_neutrino_compat})"
            )

            return (peer_info, response)

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Invalid handshake: {e}")
            raise HandshakeError(f"Invalid handshake format: {e}") from e

    def _parse_network(self, network_str: str) -> NetworkType:
        try:
            return NetworkType(network_str.lower())
        except ValueError as e:
            raise HandshakeError(f"Invalid network: {network_str}") from e

    def _parse_location(self, location: str) -> tuple[str, int]:
        if location == NOT_SERVING_ONION_HOSTNAME:
            return (NOT_SERVING_ONION_HOSTNAME, -1)

        try:
            if not location or ":" not in location:
                logger.warning(f"Incomplete location string: {location}, defaulting to not serving")
                return (NOT_SERVING_ONION_HOSTNAME, -1)

            host, port_str = location.split(":")
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port")
            return (host, port)
        except (ValueError, AttributeError) as e:
            logger.warning(f"Invalid location string: {location}, defaulting to not serving: {e}")
            return (NOT_SERVING_ONION_HOSTNAME, -1)

    def create_rejection_response(self, reason: str) -> dict:
        return create_handshake_response(
            nick=self.server_nick,
            network=self.network.value,
            accepted=False,
            motd=f"Rejected: {reason}",
        )
