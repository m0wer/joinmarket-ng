"""
Proof of Discrete Log Equivalence (PoDLE) verification for makers.

PoDLE is used to prevent sybil attacks in JoinMarket by requiring takers
to prove ownership of a UTXO without revealing which UTXO until after
the maker commits to participate.

Reference: https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8
Reference: joinmarket-clientserver/src/jmclient/podle.py
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from loguru import logger

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

PRECOMPUTED_NUMS = {
    0: bytes.fromhex("0296f47ec8e6d6a9c3379c2ce983a6752bcfa88d46f2a6ffe0dd12c9ae76d01a1f"),
    1: bytes.fromhex("023f9976b86d3f1426638da600348d96dc1f1eb0bd5614cc50db9e9a067c0464a2"),
    2: bytes.fromhex("023745b000f6db094a794d9ee08637d714393cd009f86087438ac3804e929bfe89"),
    3: bytes.fromhex("023346660dcb1f8d56e44d23f93c3ad79761cdd5f4972a638e9e15517832f6a165"),
    4: bytes.fromhex("02ec91c86964dcbb077c8193156f3cfa91476d5adfcfcf64913a4b082c75d5bca7"),
    5: bytes.fromhex("02bbc5c4393395a38446e2bd4d638b7bfd864afb5ffaf4bed4caf797df0e657434"),
    6: bytes.fromhex("02967efd39dc59e6f060bf3bd0080e8ecf4a22b9d1754924572b3e51ce2cde2096"),
    7: bytes.fromhex("02cfce8a7f9b8a1735c4d827cd84e3f2a444de1d1f7ed419d23c88d72de341357f"),
    8: bytes.fromhex("0206d6d6b1d88936bb6013ae835716f554d864954ea336e3e0141fefb2175b82f9"),
    9: bytes.fromhex("021b739f21b981c2dcbaf9af4d89223a282939a92aee079e94a46c273759e5b42e"),
}


class PoDLEError(Exception):
    pass


def get_nums_point(index: int) -> ec.EllipticCurvePublicKey:
    """Get Nothing-Up-My-Sleeve (NUMS) generator point J for given index"""
    if index not in PRECOMPUTED_NUMS:
        raise PoDLEError(f"NUMS point index {index} not supported (max 9)")

    point_bytes = PRECOMPUTED_NUMS[index]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), point_bytes)


def scalar_mult(scalar: int, point: ec.EllipticCurvePublicKey) -> ec.EllipticCurvePublicKey:
    """Multiply EC point by scalar"""
    scalar_bytes = scalar.to_bytes(32, "big")
    private_key = ec.derive_private_key(scalar, ec.SECP256K1())

    return private_key.public_key()


def point_add(
    p1: ec.EllipticCurvePublicKey, p2: ec.EllipticCurvePublicKey
) -> ec.EllipticCurvePublicKey:
    """Add two EC points"""
    p1_nums = p1.public_numbers()
    p2_nums = p2.public_numbers()

    x1, y1 = p1_nums.x, p1_nums.y
    x2, y2 = p2_nums.x, p2_nums.y

    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    if x1 == x2:
        if y1 == y2:
            s = ((3 * x1 * x1) * pow(2 * y1, p - 2, p)) % p
        else:
            raise ValueError("Points are inverses")
    else:
        s = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p

    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p

    return ec.EllipticCurvePublicNumbers(x3, y3, ec.SECP256K1()).public_key()


def verify_podle(
    P: bytes,
    P2: bytes,
    sig: bytes,
    e: bytes,
    commitment: bytes,
    index_range: range = range(10),
) -> tuple[bool, str]:
    """
    Verify PoDLE proof.

    Verifies that P and P2 have the same discrete log (private key)
    without revealing the private key itself.

    Args:
        P: Public key bytes (33 bytes compressed)
        P2: Commitment public key bytes (33 bytes compressed)
        sig: Signature s value (32 bytes)
        e: Challenge e value (32 bytes)
        commitment: sha256(P2) commitment (32 bytes)
        index_range: Allowed NUMS indices to try

    Returns:
        (is_valid, error_message)
    """
    try:
        if len(P) != 33:
            return False, f"Invalid P length: {len(P)}, expected 33"
        if len(P2) != 33:
            return False, f"Invalid P2 length: {len(P2)}, expected 33"
        if len(sig) != 32:
            return False, f"Invalid sig length: {len(sig)}, expected 32"
        if len(e) != 32:
            return False, f"Invalid e length: {len(e)}, expected 32"
        if len(commitment) != 32:
            return False, f"Invalid commitment length: {len(commitment)}, expected 32"

        expected_commitment = hashlib.sha256(P2).digest()
        if commitment != expected_commitment:
            return False, "Commitment does not match H(P2)"

        P_point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), P)
        P2_point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), P2)

        s_int = int.from_bytes(sig, "big")
        e_int = int.from_bytes(e, "big")

        if s_int >= SECP256K1_N or e_int >= SECP256K1_N:
            return False, "Signature values out of range"

        sG = scalar_mult(
            s_int,
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(),
                bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            ),
        )

        for index in index_range:
            try:
                J = get_nums_point(index)

                eP = scalar_mult(e_int, P_point)
                KG = point_add(sG, eP)

                sJ = scalar_mult(s_int, J)
                eP2 = scalar_mult(e_int, P2_point)
                KJ = point_add(sJ, eP2)

                KG_bytes = KG.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.CompressedPoint,
                )
                KJ_bytes = KJ.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.CompressedPoint,
                )

                e_check = hashlib.sha256(KG_bytes + KJ_bytes + P + P2).digest()

                if e_check == e:
                    logger.debug(f"PoDLE verification successful at index {index}")
                    return True, ""

            except Exception as ex:
                logger.debug(f"PoDLE verification failed at index {index}: {ex}")
                continue

        return False, f"PoDLE verification failed for all indices in {index_range}"

    except Exception as ex:
        logger.error(f"PoDLE verification error: {ex}")
        return False, f"Verification error: {ex}"


def parse_podle_revelation(revelation: dict[str, Any]) -> dict[str, Any] | None:
    """
    Parse and validate PoDLE revelation structure.

    Expected format from taker:
    {
        'P': <hex string>,
        'P2': <hex string>,
        'sig': <hex string>,
        'e': <hex string>,
        'utxo': <txid:vout string>
    }

    Returns parsed structure or None if invalid.
    """
    try:
        required_fields = ["P", "P2", "sig", "e", "utxo"]
        for field in required_fields:
            if field not in revelation:
                logger.warning(f"Missing required field in PoDLE revelation: {field}")
                return None

        P_bytes = bytes.fromhex(revelation["P"])
        P2_bytes = bytes.fromhex(revelation["P2"])
        sig_bytes = bytes.fromhex(revelation["sig"])
        e_bytes = bytes.fromhex(revelation["e"])

        utxo_parts = revelation["utxo"].split(":")
        if len(utxo_parts) != 2:
            logger.warning(f"Invalid UTXO format: {revelation['utxo']}")
            return None

        txid = utxo_parts[0]
        vout = int(utxo_parts[1])

        return {
            "P": P_bytes,
            "P2": P2_bytes,
            "sig": sig_bytes,
            "e": e_bytes,
            "txid": txid,
            "vout": vout,
        }

    except Exception as e:
        logger.error(f"Failed to parse PoDLE revelation: {e}")
        return None


def deserialize_revelation(revelation_str: str) -> dict[str, Any] | None:
    """
    Deserialize PoDLE revelation from wire format.

    Format: P|P2|sig|e|utxo (pipe-separated hex strings)
    """
    try:
        parts = revelation_str.split("|")
        if len(parts) != 5:
            logger.warning(f"Invalid revelation format: expected 5 parts, got {len(parts)}")
            return None

        return {
            "P": parts[0],
            "P2": parts[1],
            "sig": parts[2],
            "e": parts[3],
            "utxo": parts[4],
        }

    except Exception as e:
        logger.error(f"Failed to deserialize PoDLE revelation: {e}")
        return None
