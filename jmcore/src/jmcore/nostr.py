"""
Nostr protocol support for JoinMarket.
Handles event creation, signing, and serialization.
"""

import hashlib
import json
import time

import coincurve
from loguru import logger
from pydantic import BaseModel, Field

from jmcore.models import Offer


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class NostrEvent(BaseModel):
    id: str = Field(..., min_length=64, max_length=64)
    pubkey: str = Field(..., min_length=64, max_length=64)
    created_at: int
    kind: int
    tags: list[list[str]] = Field(default_factory=list)
    content: str
    sig: str = Field(..., min_length=128, max_length=128)

    def serialize(self) -> bytes:
        """
        Serialize event for ID generation and signing as per NIP-01.
        [0, pubkey, created_at, kind, tags, content]
        """
        data = [
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]
        # separators=(',', ':') removes whitespace
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def create(
        kind: int,
        content: str,
        tags: list[list[str]],
        private_key_hex: str,
        created_at: int | None = None,
    ) -> "NostrEvent":
        if created_at is None:
            created_at = int(time.time())

        # Ensure private key is bytes
        priv_key_bytes = bytes.fromhex(private_key_hex)

        # Derive public key (x-only)
        priv_key = coincurve.PrivateKey(priv_key_bytes)
        pub_key_hex = priv_key.public_key.format(compressed=True)[1:].hex()

        # Temporary event to calculate ID
        temp_event_data = [
            0,
            pub_key_hex,
            created_at,
            kind,
            tags,
            content,
        ]
        serialized = json.dumps(temp_event_data, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        event_id = hashlib.sha256(serialized).hexdigest()

        # Sign
        sig_bytes = priv_key.sign_schnorr(bytes.fromhex(event_id))
        sig_hex = sig_bytes.hex()

        return NostrEvent(
            id=event_id,
            pubkey=pub_key_hex,
            created_at=created_at,
            kind=kind,
            tags=tags,
            content=content,
            sig=sig_hex,
        )

    def verify(self) -> bool:
        # 1. Verify ID
        serialized = self.serialize()
        calc_id = hashlib.sha256(serialized).hexdigest()
        if calc_id != self.id:
            logger.warning(f"ID mismatch: {calc_id} != {self.id}")
            return False

        # 2. Verify Schnorr signature (BIP-340)
        try:
            pub_key_bytes = bytes.fromhex(self.pubkey)
            return coincurve.PublicKeyXOnly(pub_key_bytes).verify(
                bytes.fromhex(self.sig), bytes.fromhex(self.id)
            )
        except Exception:
            return False


class OfferEventFactory:
    # Parameterized replaceable event (NIP-33 range: 30000-39999).
    # 31402 is an arbitrary choice for JoinMarket offers - not standardized.
    KIND_JM_OFFER = 31402

    @staticmethod
    def create_offer_event(offer: Offer, private_key_hex: str) -> NostrEvent:
        """
        Creates a Nostr event for a JoinMarket Offer.
        """
        content = offer.model_dump_json()

        # Tags for indexing/filtering
        tags = [
            ["d", f"offer-{offer.oid}"],  # Identifier for addressable event
            ["t", "joinmarket-offer"],
            ["f", offer.ordertype.value],
            ["c", offer.cjfee if isinstance(offer.cjfee, str) else str(offer.cjfee)],
            ["v", str(offer.fidelity_bond_value)],
        ]

        return NostrEvent.create(
            kind=OfferEventFactory.KIND_JM_OFFER,
            content=content,
            tags=tags,
            private_key_hex=private_key_hex,
        )
