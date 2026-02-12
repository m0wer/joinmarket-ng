"""
Cold wallet workflow: create-bond-address, generate-hot-keypair,
prepare-certificate-message, import-certificate + crypto verification helpers.
"""

from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from jmcore.cli_common import setup_logging
from loguru import logger

from jmwallet.cli import app


@app.command("create-bond-address")
def create_bond_address(
    pubkey: Annotated[str, typer.Argument(help="Public key (hex, 33 bytes compressed)")],
    locktime: Annotated[
        int, typer.Option("--locktime", "-L", help="Locktime as Unix timestamp")
    ] = 0,
    locktime_date: Annotated[
        str | None,
        typer.Option(
            "--locktime-date", "-d", help="Locktime as date (YYYY-MM, must be 1st of month)"
        ),
    ] = None,
    network: Annotated[str, typer.Option("--network", "-n")] = "mainnet",
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    no_save: Annotated[
        bool,
        typer.Option("--no-save", help="Do not save the bond to the registry"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """
    Create a fidelity bond address from a public key (cold wallet workflow).

    This command creates a timelocked P2WSH bond address from a public key WITHOUT
    requiring your mnemonic or private keys. Use this for true cold storage security.

    WORKFLOW:
    1. Use Sparrow Wallet (or similar) with your hardware wallet
    2. Navigate to your wallet's receive addresses
    3. Find or create an address at the fidelity bond derivation path (m/84'/0'/0'/2/0)
    4. Copy the public key from the address details
    5. Use this command with the public key to create the bond address
    6. Fund the bond address from any wallet
    7. Use 'prepare-certificate-message' and hardware wallet signing for certificates

    Your hardware wallet never needs to be connected to this online tool.
    """
    setup_logging(log_level)

    # Validate pubkey
    try:
        pubkey_bytes = bytes.fromhex(pubkey)
        if len(pubkey_bytes) != 33:
            raise ValueError("Public key must be 33 bytes (compressed)")
        # Verify it's a valid compressed pubkey (starts with 02 or 03)
        if pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")
    except ValueError as e:
        logger.error(f"Invalid public key: {e}")
        raise typer.Exit(1)

    # Parse locktime
    from jmcore.timenumber import is_valid_locktime, parse_locktime_date

    if locktime_date:
        try:
            locktime = parse_locktime_date(locktime_date)
        except ValueError as e:
            logger.error(f"Invalid locktime date: {e}")
            logger.info("Use format: YYYY-MM or YYYY-MM-DD (must be 1st of month)")
            logger.info("Valid range: 2020-01 to 2099-12")
            raise typer.Exit(1)

    if locktime <= 0:
        logger.error("Locktime is required. Use --locktime or --locktime-date")
        raise typer.Exit(1)

    # Validate locktime is a valid timenumber (1st of month, midnight UTC)
    if not is_valid_locktime(locktime):
        from jmcore.timenumber import get_nearest_valid_locktime

        suggested = get_nearest_valid_locktime(locktime, round_up=True)
        suggested_dt = datetime.fromtimestamp(suggested)
        logger.warning(
            f"Locktime {locktime} is not a valid fidelity bond locktime "
            f"(must be 1st of month at midnight UTC)"
        )
        logger.info(f"Suggested locktime: {suggested} ({suggested_dt.strftime('%Y-%m-%d')})")
        logger.info("Use --locktime-date YYYY-MM for correct format")
        raise typer.Exit(1)

    # Validate locktime is in the future
    if locktime <= datetime.now().timestamp():
        logger.warning("Locktime is in the past - the bond will be immediately spendable")

    from jmcore.btc_script import disassemble_script, mk_freeze_script
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.address import script_to_p2wsh_address
    from jmwallet.wallet.bond_registry import (
        create_bond_info,
        load_registry,
        save_registry,
    )

    # Create the witness script from the public key
    witness_script = mk_freeze_script(pubkey, locktime)
    address = script_to_p2wsh_address(witness_script, network)

    locktime_dt = datetime.fromtimestamp(locktime)
    disassembled = disassemble_script(witness_script)

    # Resolve data directory
    resolved_data_dir = data_dir if data_dir else get_default_data_dir()

    # Save to registry unless --no-save
    saved = False
    existing = False
    if not no_save:
        registry = load_registry(resolved_data_dir)
        existing_bond = registry.get_bond_by_address(address)
        if existing_bond:
            existing = True
            logger.info(f"Bond already exists in registry (created: {existing_bond.created_at})")
        else:
            # For bonds created from pubkey, we don't have the derivation path or index
            # So we use placeholder values
            bond_info = create_bond_info(
                address=address,
                locktime=locktime,
                index=-1,  # Unknown index for pubkey-based bonds
                path="external",  # Path is unknown when created from pubkey
                pubkey_hex=pubkey,
                witness_script=witness_script,
                network=network,
            )
            registry.add_bond(bond_info)
            save_registry(registry, resolved_data_dir)
            saved = True

    # Compute the underlying P2WPKH address for the pubkey (for user confirmation)
    from jmwallet.wallet.address import pubkey_to_p2wpkh_address

    p2wpkh_address = pubkey_to_p2wpkh_address(bytes.fromhex(pubkey), network)

    print("\n" + "=" * 80)
    print("FIDELITY BOND ADDRESS (created from public key)")
    print("=" * 80)
    print(f"\nBond Address (P2WSH):  {address}")
    print(f"Signing Address:       {p2wpkh_address}")
    print("  (Use this address in Sparrow to sign messages)")
    print(f"Locktime:              {locktime} ({locktime_dt.strftime('%Y-%m-%d %H:%M:%S')})")
    print(f"Network:               {network}")
    print(f"Public Key:            {pubkey}")
    print()
    print("-" * 80)
    print("WITNESS SCRIPT (redeemScript)")
    print("-" * 80)
    print(f"Hex:          {witness_script.hex()}")
    print(f"Disassembled: {disassembled}")
    print("-" * 80)
    if saved:
        print(f"\nSaved to registry: {resolved_data_dir / 'fidelity_bonds.json'}")
    elif existing:
        print("\nBond already in registry (not updated)")
    elif no_save:
        print("\nNot saved to registry (--no-save)")
    print("\n" + "=" * 80)
    print("HOW TO GET PUBLIC KEY FROM SPARROW WALLET:")
    print("=" * 80)
    print("  1. Open Sparrow Wallet and connect your hardware wallet")
    print("  2. Go to Addresses tab")
    print("  3. Choose any address from the Deposit (m/84'/0'/0'/0/x) or")
    print("     Change (m/84'/0'/0'/1/x) account - use index 0 for simplicity")
    print("  4. Right-click the address and select 'Copy Public Key'")
    print("  5. Use the copied public key with this command")
    print()
    print("NOTE: The /2 fidelity bond derivation path is NOT available in Sparrow.")
    print("      Using /0 (deposit) or /1 (change) addresses works fine.")
    print()
    print("IMPORTANT:")
    print("  - Funds sent to the Bond Address are LOCKED until the locktime!")
    print("  - Remember which address you used for the bond's public key")
    print("  - Your private keys never leave the hardware wallet")
    print("=" * 80 + "\n")


@app.command("generate-hot-keypair")
def generate_hot_keypair(
    bond_address: Annotated[
        str | None,
        typer.Option(
            "--bond-address",
            help="Bond address to associate keypair with (saves to registry)",
        ),
    ] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Generate a hot wallet keypair for fidelity bond certificates.

    This generates a random keypair that will be used for signing nick messages
    in the fidelity bond proof. The private key stays in the hot wallet, while
    the public key is used to create a certificate signed by the cold wallet.

    The certificate chain is:
      UTXO keypair (cold) -> signs -> certificate (hot) -> signs -> nick proofs

    If --bond-address is provided, the keypair is saved to the bond registry
    and will be automatically used when importing the certificate.

    SECURITY:
    - The hot wallet private key should be stored securely
    - If compromised, an attacker can impersonate your bond until cert expires
    - But they CANNOT spend your bond funds (those remain in cold storage)
    """
    setup_logging(log_level)

    from coincurve import PrivateKey
    from jmcore.paths import get_default_data_dir

    # Generate a random private key
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    # Optionally save to registry
    saved_to_registry = False
    if bond_address:
        from jmwallet.wallet.bond_registry import load_registry, save_registry

        resolved_data_dir = data_dir if data_dir else get_default_data_dir()
        registry = load_registry(resolved_data_dir)
        bond = registry.get_bond_by_address(bond_address)

        if bond:
            bond.cert_pubkey = pubkey.hex()
            bond.cert_privkey = privkey.secret.hex()
            save_registry(registry, resolved_data_dir)
            saved_to_registry = True
            logger.info(f"Saved hot keypair to bond registry for {bond_address}")
        else:
            logger.warning(f"Bond not found for address: {bond_address}")
            logger.info("Keypair will be displayed but NOT saved to registry")

    print("\n" + "=" * 80)
    print("HOT WALLET KEYPAIR FOR FIDELITY BOND CERTIFICATE")
    print("=" * 80)
    print(f"\nPrivate Key (hex): {privkey.secret.hex()}")
    print(f"Public Key (hex):  {pubkey.hex()}")
    if saved_to_registry:
        print(f"\nSaved to bond registry for: {bond_address}")
        print("  (The keypair will be used automatically with import-certificate)")
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("  1. Use the public key with 'prepare-certificate-message'")
    print("  2. Sign the certificate message with your hardware wallet (Sparrow)")
    print("  3. Import the certificate with 'import-certificate'")
    if not saved_to_registry:
        print("\nNOTE: Store the private key securely! You will need it for import-certificate.")
    print("\nSECURITY:")
    print("  - This is the HOT wallet key - it will be used to sign nick proofs")
    print("  - If this key is compromised, attacker can impersonate your bond")
    print("  - But your BOND FUNDS remain safe in cold storage!")
    print("=" * 80 + "\n")


@app.command("prepare-certificate-message")
def prepare_certificate_message(
    bond_address: Annotated[str, typer.Argument(help="Bond P2WSH address")],
    cert_pubkey: Annotated[
        str | None,
        typer.Option("--cert-pubkey", help="Certificate public key (hex)"),
    ] = None,
    validity_periods: Annotated[
        int,
        typer.Option(
            "--validity-periods",
            help="Certificate validity in 2016-block periods from now (1=~2wk, 52=~2yr)",
        ),
    ] = 52,  # ~2 years validity
    data_dir_opt: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    mempool_api: Annotated[
        str,
        typer.Option("--mempool-api", help="Mempool API URL for fetching block height"),
    ] = "https://mempool.space/api",
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Prepare certificate message for signing with hardware wallet (cold wallet support).

    This generates the message that needs to be signed by the bond UTXO's private key.
    The message can then be signed using a hardware wallet via tools like Sparrow Wallet.

    IMPORTANT: This command does NOT require your mnemonic or private keys.
    It only prepares the message that you will sign with your hardware wallet.

    If --cert-pubkey is not provided and the bond already has a hot keypair saved
    in the registry (from generate-hot-keypair --bond-address), it will be used.

    The certificate message format for Sparrow is plain ASCII text:
      "fidelity-bond-cert|<cert_pubkey_hex>|<cert_expiry>"

    Where cert_expiry is the ABSOLUTE period number (current_period + validity_periods).
    The reference implementation validates that current_block < cert_expiry * 2016.
    """
    setup_logging(log_level)

    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry

    # Resolve data directory
    data_dir = data_dir_opt if data_dir_opt else get_default_data_dir()
    registry = load_registry(data_dir)
    bond = registry.get_bond_by_address(bond_address)

    if not bond:
        logger.error(f"Bond not found for address: {bond_address}")
        logger.info("Make sure you have created the bond with 'create-bond-address' first")
        raise typer.Exit(1)

    # Get cert_pubkey from argument or registry
    if not cert_pubkey:
        if bond.cert_pubkey:
            cert_pubkey = bond.cert_pubkey
            logger.info("Using certificate pubkey from bond registry")
        else:
            logger.error("--cert-pubkey is required")
            logger.info(
                "Run 'generate-hot-keypair --bond-address <addr>' first, or provide --cert-pubkey"
            )
            raise typer.Exit(1)

    # Validate cert_pubkey
    try:
        cert_pubkey_bytes = bytes.fromhex(cert_pubkey)
        if len(cert_pubkey_bytes) != 33:
            raise ValueError("Certificate pubkey must be 33 bytes (compressed)")
        if cert_pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")
    except ValueError as e:
        logger.error(f"Invalid certificate pubkey: {e}")
        raise typer.Exit(1)

    # Fetch current block height from mempool API
    import urllib.request

    try:
        with urllib.request.urlopen(f"{mempool_api}/blocks/tip/height", timeout=10) as response:
            current_block_height = int(response.read().decode())
        logger.info(f"Current block height: {current_block_height}")
    except Exception as e:
        logger.error(f"Failed to fetch block height from {mempool_api}: {e}")
        logger.info("You can specify a different API with --mempool-api")
        raise typer.Exit(1)

    # Calculate cert_expiry as ABSOLUTE period number
    # Reference: yieldgenerator.py line 139
    # cert_expiry = ((blocks + BLOCK_COUNT_SAFETY) // RETARGET_INTERVAL) + CERT_MAX_VALIDITY_TIME
    retarget_interval = 2016
    block_count_safety = 2
    current_period = (current_block_height + block_count_safety) // retarget_interval
    cert_expiry = current_period + validity_periods

    # Validate cert_expiry fits in 2 bytes (uint16)
    if cert_expiry > 65535:
        logger.error(f"cert_expiry {cert_expiry} exceeds maximum 65535")
        raise typer.Exit(1)

    # Calculate expiry details for display
    expiry_block = cert_expiry * retarget_interval
    blocks_until_expiry = expiry_block - current_block_height
    weeks_until_expiry = blocks_until_expiry // 2016 * 2

    # Create ASCII certificate message (hex pubkey - compatible with Sparrow text input)
    # This format allows users to paste directly into Sparrow's message field
    cert_msg_ascii = f"fidelity-bond-cert|{cert_pubkey}|{cert_expiry}"

    # Save message to file for easier signing workflows
    data_dir.mkdir(parents=True, exist_ok=True)
    message_file = data_dir / "certificate_message.txt"
    message_file.write_text(cert_msg_ascii)

    # Get the signing address (P2WPKH address for the bond's pubkey)
    from jmwallet.wallet.address import pubkey_to_p2wpkh_address

    bond_pubkey = bytes.fromhex(bond.pubkey)
    # Determine network from bond
    signing_address = pubkey_to_p2wpkh_address(bond_pubkey, bond.network)

    print("\n" + "=" * 80)
    print("FIDELITY BOND CERTIFICATE MESSAGE")
    print("=" * 80)
    print(f"\nBond Address (P2WSH):  {bond_address}")
    print(f"Signing Address:       {signing_address}")
    print("  (Select this address in Sparrow to sign)")
    print(f"Certificate Pubkey:    {cert_pubkey}")
    print(f"\nCurrent Block:         {current_block_height} (period {current_period})")
    print(f"Cert Expiry:           period {cert_expiry} (block {expiry_block})")
    print(f"Validity:              ~{weeks_until_expiry} weeks ({blocks_until_expiry} blocks)")
    print("\n" + "-" * 80)
    print("MESSAGE TO SIGN (copy this EXACTLY into Sparrow):")
    print("-" * 80)
    print(cert_msg_ascii)
    print("-" * 80)
    print(f"\nMessage saved to: {message_file}")
    print("\n" + "=" * 80)
    print("HOW TO SIGN THIS MESSAGE:")
    print("=" * 80)
    print()
    print("Sparrow Wallet with Hardware Wallet:")
    print("  1. Open Sparrow Wallet and connect your hardware wallet")
    print("  2. Go to Tools -> Sign/Verify Message")
    print(f"  3. Select the Signing Address shown above: {signing_address}")
    print("  4. Copy the entire message above (fidelity-bond-cert|...) and")
    print("     paste it into the 'Message' field in Sparrow")
    print("  5. Select 'Standard (Electrum)' format (NOT BIP322)")
    print("  6. Click 'Sign Message' - hardware wallet will prompt for confirmation")
    print("  7. Copy the resulting base64 signature")
    print()
    print("After signing, use 'jm-wallet import-certificate' with the signature.")
    print("=" * 80 + "\n")


def _verify_recoverable_signature(
    sig_bytes: bytes, cert_pubkey_hex: str, cert_expiry: int, expected_pubkey: bytes
) -> bool:
    """
    Verify a 65-byte recoverable signature (Sparrow/Electrum format).

    Electrum format: 1 byte header + 32 bytes R + 32 bytes S
    Header encodes recovery ID: 27-30 for uncompressed, 31-34 for compressed.

    coincurve format: 32 bytes R + 32 bytes S + 1 byte recovery_id

    Returns True if the recovered pubkey matches expected_pubkey.
    """
    from coincurve import PublicKey
    from jmcore.crypto import bitcoin_message_hash_bytes

    if len(sig_bytes) != 65:
        return False

    header = sig_bytes[0]
    r = sig_bytes[1:33]
    s = sig_bytes[33:65]

    # Determine recovery ID from header
    # 27-30: uncompressed pubkey recovery
    # 31-34: compressed pubkey recovery (Electrum/Sparrow default)
    if 31 <= header <= 34:
        recovery_id = header - 31
        compressed = True
    elif 27 <= header <= 30:
        recovery_id = header - 27
        compressed = False
    else:
        logger.warning(f"Unknown signature header byte: {header}")
        return False

    # coincurve expects: r (32) + s (32) + recovery_id (1)
    coincurve_sig = r + s + bytes([recovery_id])

    # Try ASCII message format (what Sparrow signed with our new CLI)
    ascii_msg = f"fidelity-bond-cert|{cert_pubkey_hex}|{cert_expiry}".encode()
    msg_hash = bitcoin_message_hash_bytes(ascii_msg)

    try:
        recovered_pk = PublicKey.from_signature_and_message(coincurve_sig, msg_hash, hasher=None)
        recovered_pubkey = recovered_pk.format(compressed=compressed)

        if recovered_pubkey == expected_pubkey:
            logger.debug("Signature verified with ASCII message format")
            return True
    except Exception as e:
        logger.debug(f"Recovery failed with ASCII format: {e}")

    # Try binary format (raw pubkey bytes) as fallback
    cert_pubkey_bytes = bytes.fromhex(cert_pubkey_hex)
    binary_msg = (
        b"fidelity-bond-cert|" + cert_pubkey_bytes + b"|" + str(cert_expiry).encode("ascii")
    )
    msg_hash = bitcoin_message_hash_bytes(binary_msg)

    try:
        recovered_pk = PublicKey.from_signature_and_message(coincurve_sig, msg_hash, hasher=None)
        recovered_pubkey = recovered_pk.format(compressed=compressed)

        if recovered_pubkey == expected_pubkey:
            logger.debug("Signature verified with binary message format")
            return True
    except Exception as e:
        logger.debug(f"Recovery failed with binary format: {e}")

    # Try hex-as-text format (user pasted hex into Sparrow's message field)
    # This handles the case where user pasted the old CLI's hex output
    hex_msg = (
        b"fidelity-bond-cert|" + cert_pubkey_bytes + b"|" + str(cert_expiry).encode("ascii")
    ).hex()
    hex_as_text_msg = hex_msg.encode("utf-8")
    msg_hash = bitcoin_message_hash_bytes(hex_as_text_msg)

    try:
        recovered_pk = PublicKey.from_signature_and_message(coincurve_sig, msg_hash, hasher=None)
        recovered_pubkey = recovered_pk.format(compressed=compressed)

        if recovered_pubkey == expected_pubkey:
            logger.debug("Signature verified with hex-as-text message format")
            return True
    except Exception as e:
        logger.debug(f"Recovery failed with hex-as-text format: {e}")

    return False


def _verify_der_signature(
    sig_bytes: bytes, cert_pubkey_hex: str, cert_expiry: int, expected_pubkey: bytes
) -> bool:
    """
    Verify a DER-encoded signature.

    Tries both ASCII and binary message formats.
    """
    from jmcore.crypto import bitcoin_message_hash_bytes, verify_raw_ecdsa

    cert_pubkey_bytes = bytes.fromhex(cert_pubkey_hex)

    # Try ASCII format first
    ascii_msg = f"fidelity-bond-cert|{cert_pubkey_hex}|{cert_expiry}".encode()
    msg_hash = bitcoin_message_hash_bytes(ascii_msg)

    if verify_raw_ecdsa(msg_hash, sig_bytes, expected_pubkey):
        logger.debug("DER signature verified with ASCII format")
        return True

    # Try binary format
    binary_msg = (
        b"fidelity-bond-cert|" + cert_pubkey_bytes + b"|" + str(cert_expiry).encode("ascii")
    )
    msg_hash = bitcoin_message_hash_bytes(binary_msg)

    if verify_raw_ecdsa(msg_hash, sig_bytes, expected_pubkey):
        logger.debug("DER signature verified with binary format")
        return True

    return False


def _recoverable_to_der(sig_bytes: bytes) -> bytes:
    """
    Convert a 65-byte recoverable signature to DER format.

    Format in: 1 byte header + 32 bytes R + 32 bytes S
    Format out: DER-encoded signature
    """
    if len(sig_bytes) != 65:
        return sig_bytes

    r = sig_bytes[1:33]
    s = sig_bytes[33:65]

    def encode_int(val: bytes) -> bytes:
        # Remove leading zeros but keep one if MSB is set
        val = val.lstrip(b"\x00") or b"\x00"
        if val[0] & 0x80:
            val = b"\x00" + val
        return bytes([len(val)]) + val

    r_enc = encode_int(r)
    s_enc = encode_int(s)

    sig_body = b"\x02" + r_enc + b"\x02" + s_enc
    return b"\x30" + bytes([len(sig_body)]) + sig_body


@app.command("import-certificate")
def import_certificate(
    address: Annotated[str, typer.Argument(help="Bond address")],
    cert_pubkey: Annotated[
        str | None, typer.Option("--cert-pubkey", help="Certificate pubkey (hex)")
    ] = None,
    cert_privkey: Annotated[
        str | None, typer.Option("--cert-privkey", help="Certificate private key (hex)")
    ] = None,
    cert_signature: Annotated[
        str, typer.Option("--cert-signature", help="Certificate signature (base64)")
    ] = "",
    cert_expiry: Annotated[
        int,
        typer.Option(
            "--cert-expiry",
            help="Certificate expiry as ABSOLUTE period number (from prepare-certificate-message)",
        ),
    ] = 0,  # 0 means "must be provided"
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    skip_verification: Annotated[
        bool,
        typer.Option("--skip-verification", help="Skip signature verification (not recommended)"),
    ] = False,
    mempool_api: Annotated[
        str,
        typer.Option("--mempool-api", help="Mempool API URL for fetching block height"),
    ] = "https://mempool.space/api",
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Import a certificate signature for a fidelity bond (cold wallet support).

    This imports a certificate generated with 'prepare-certificate-message' into the
    bond registry, allowing the hot wallet to use it for making offers.

    IMPORTANT: The --cert-expiry value must match EXACTLY what was used in
    prepare-certificate-message. This is an ABSOLUTE period number, not a duration.

    If --cert-pubkey and --cert-privkey are not provided, they will be loaded from
    the bond registry (from a previous 'generate-hot-keypair --bond-address' call).

    The signature should be the base64 output from Sparrow's message signing tool,
    using the 'Standard (Electrum)' format.
    """
    setup_logging(log_level)

    from coincurve import PrivateKey
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry, save_registry

    # Load registry first to get bond info
    resolved_data_dir = data_dir if data_dir else get_default_data_dir()
    registry = load_registry(resolved_data_dir)

    # Find bond by address
    bond = registry.get_bond_by_address(address)
    if not bond:
        logger.error(f"Bond not found for address: {address}")
        logger.info("Make sure you have created the bond with 'create-bond-address' first")
        raise typer.Exit(1)

    # Get cert_pubkey and cert_privkey from arguments or registry
    if not cert_pubkey:
        if bond.cert_pubkey:
            cert_pubkey = bond.cert_pubkey
            logger.info("Using certificate pubkey from bond registry")
        else:
            logger.error("--cert-pubkey is required")
            logger.info("Run 'generate-hot-keypair --bond-address <addr>' first")
            raise typer.Exit(1)

    if not cert_privkey:
        if bond.cert_privkey:
            cert_privkey = bond.cert_privkey
            logger.info("Using certificate privkey from bond registry")
        else:
            logger.error("--cert-privkey is required")
            logger.info("Run 'generate-hot-keypair --bond-address <addr>' first")
            raise typer.Exit(1)

    if not cert_signature:
        logger.error("--cert-signature is required")
        raise typer.Exit(1)

    # Validate cert_expiry is provided
    if cert_expiry == 0:
        logger.error("--cert-expiry is required")
        logger.info("Use the same value shown by 'prepare-certificate-message'")
        raise typer.Exit(1)

    # Fetch current block height to validate cert_expiry is in the future
    import urllib.request

    try:
        with urllib.request.urlopen(f"{mempool_api}/blocks/tip/height", timeout=10) as response:
            current_block_height = int(response.read().decode())
        logger.debug(f"Current block height: {current_block_height}")
    except Exception as e:
        logger.warning(f"Failed to fetch block height: {e}")
        current_block_height = None

    # Validate cert_expiry is in the future
    retarget_interval = 2016
    if current_block_height is not None:
        expiry_block = cert_expiry * retarget_interval
        if current_block_height >= expiry_block:
            logger.error("Certificate has ALREADY EXPIRED!")
            logger.error(f"  Current block: {current_block_height}")
            logger.error(f"  Cert expiry:   period {cert_expiry} (block {expiry_block})")
            logger.info("Run 'prepare-certificate-message' again with current block height")
            logger.info("and re-sign the new message with your hardware wallet.")
            raise typer.Exit(1)

        blocks_remaining = expiry_block - current_block_height
        weeks_remaining = blocks_remaining // retarget_interval * 2
        logger.info(f"Certificate valid for ~{weeks_remaining} weeks ({blocks_remaining} blocks)")

    # Validate inputs
    try:
        cert_pubkey_bytes = bytes.fromhex(cert_pubkey)
        if len(cert_pubkey_bytes) != 33:
            raise ValueError("Certificate pubkey must be 33 bytes")
        if cert_pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")

        cert_privkey_bytes = bytes.fromhex(cert_privkey)
        if len(cert_privkey_bytes) != 32:
            raise ValueError("Certificate privkey must be 32 bytes")

        # Decode signature from base64 (Sparrow output)
        try:
            cert_sig_bytes = base64.b64decode(cert_signature)
        except Exception:
            # Try hex format as fallback
            try:
                cert_sig_bytes = bytes.fromhex(cert_signature)
            except Exception:
                raise ValueError("Signature must be base64 (from Sparrow) or hex encoded")

        # Verify that privkey matches pubkey
        privkey = PrivateKey(cert_privkey_bytes)
        derived_pubkey = privkey.public_key.format(compressed=True)
        if derived_pubkey != cert_pubkey_bytes:
            raise ValueError("Certificate privkey does not match cert_pubkey!")

    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        raise typer.Exit(1)

    # Get the bond's utxo pubkey
    utxo_pubkey = bytes.fromhex(bond.pubkey)

    # Verify certificate signature (unless skipped)
    if not skip_verification:
        # The signature from Sparrow is a 65-byte recoverable signature:
        # 1 byte header (recovery ID + 27 for compressed) + 32 bytes R + 32 bytes S
        if len(cert_sig_bytes) == 65:
            logger.info("Detected 65-byte recoverable signature (Sparrow/Electrum format)")
            verified = _verify_recoverable_signature(
                cert_sig_bytes, cert_pubkey, cert_expiry, utxo_pubkey
            )
        else:
            # Try DER format
            logger.info(f"Signature is {len(cert_sig_bytes)} bytes, trying DER format")
            verified = _verify_der_signature(cert_sig_bytes, cert_pubkey, cert_expiry, utxo_pubkey)

        if not verified:
            logger.error("Certificate signature verification failed!")
            logger.error("The signature does not match the bond's public key.")
            logger.info("Make sure you:")
            logger.info("  1. Selected the correct signing address in Sparrow")
            logger.info("  2. Copied the message EXACTLY as shown by prepare-certificate-message")
            logger.info("  3. Used 'Standard (Electrum)' format in Sparrow")
            raise typer.Exit(1)

        logger.info("Certificate signature verified successfully")
    else:
        logger.warning("Skipping signature verification - use at your own risk!")

    # Convert recoverable signature to DER format for storage
    # The maker code expects DER signatures
    if len(cert_sig_bytes) == 65:
        der_sig = _recoverable_to_der(cert_sig_bytes)
    else:
        der_sig = cert_sig_bytes

    # Update bond with certificate
    bond.cert_pubkey = cert_pubkey
    bond.cert_privkey = cert_privkey
    bond.cert_signature = der_sig.hex()  # Store as hex DER
    bond.cert_expiry = cert_expiry

    save_registry(registry, resolved_data_dir)

    # Calculate expiry info for display
    expiry_block = cert_expiry * retarget_interval
    if current_block_height is not None:
        blocks_remaining = expiry_block - current_block_height
        weeks_remaining = blocks_remaining // retarget_interval * 2
        expiry_info = f"~{weeks_remaining} weeks remaining"
    else:
        expiry_info = "could not verify"

    print("\n" + "=" * 80)
    print("CERTIFICATE IMPORTED SUCCESSFULLY")
    print("=" * 80)
    print(f"\nBond Address:          {address}")
    print(f"Certificate Pubkey:    {cert_pubkey}")
    print(f"Certificate Expiry:    period {cert_expiry} (block {expiry_block}, {expiry_info})")
    print(f"\nRegistry updated: {resolved_data_dir / 'fidelity_bonds.json'}")
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("  The maker bot will automatically use this certificate when creating")
    print("  fidelity bond proofs. Your cold wallet private key is never needed!")
    print("=" * 80 + "\n")
