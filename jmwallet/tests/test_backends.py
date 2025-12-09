"""
Integration tests for BitcoinCoreBackend
"""

import pytest
from jmcore.crypto import KeyPair

from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.address import pubkey_to_p2wpkh_address


@pytest.mark.asyncio
async def test_bitcoin_core_backend_integration():
    # Connect to the regtest node defined in docker-compose
    backend = BitcoinCoreBackend(
        rpc_url="http://localhost:18443", rpc_user="test", rpc_password="test"
    )

    try:
        # Check connection
        try:
            await backend.get_block_height()
        except Exception:
            pytest.skip("Bitcoin Core not available at localhost:18443")
            return

        # Generate a local address
        kp = KeyPair()
        # "regtest" usually implies "bcrt" prefix in our address helper
        address = pubkey_to_p2wpkh_address(kp.public_key_hex(), network="regtest")

        # Mine to this address
        try:
            # generatetoaddress 1 block
            block_hashes = await backend._rpc_call("generatetoaddress", [1, address])
        except Exception as e:
            # If this fails, we can't really test UTXO scanning easily
            pytest.fail(f"generatetoaddress failed: {e}")

        assert len(block_hashes) == 1

        # Test get_utxos
        utxos = await backend.get_utxos([address])

        assert len(utxos) > 0
        assert sum(u.value for u in utxos) > 0

        # Test get_address_balance
        balance = await backend.get_address_balance(address)
        assert balance > 0

        # Test get_transaction using the found UTXO
        txid = utxos[0].txid

        tx = await backend.get_transaction(txid)
        assert tx is not None
        assert tx.txid == txid

        # Test estimate_fee
        fee = await backend.estimate_fee(2)
        assert fee > 0

    finally:
        await backend.close()
