# Integration Tests

## Prerequisites

- Docker and Docker Compose
- Python 3.14+
- pytest and pytest-asyncio

## Setup

1. **Start Bitcoin regtest node and directory server:**

```bash
cd maker/tests/integration
docker-compose up -d
```

2. **Wait for Bitcoin Core to be ready (about 30 seconds):**

```bash
docker-compose logs -f bitcoin
# Wait until you see "Initial setup: mining to mature coinbase (block 100/101)"
```

3. **Verify Bitcoin Core is accessible:**

```bash
docker exec jm-bitcoin-test bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo
```

## Running Tests

```bash
# From the maker directory
cd /home/m0u/code/bitcoin/jm-refactor/maker

# Install dependencies
pip install -e ../jmwallet[dev]
pip install -e .

# Run integration tests
pytest tests/integration/test_wallet_bitcoin_core.py -v

# Run with coverage
pytest tests/integration/test_wallet_bitcoin_core.py -v --cov=jmwallet
```

## Manual Testing

```python
import asyncio
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService

async def test():
    # Connect to regtest Bitcoin Core
    backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test"
    )

    # Check connection
    height = await backend.get_block_height()
    print(f"Block height: {height}")

    # Create wallet
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network="regtest"
    )

    # Generate address
    addr = wallet.get_receive_address(0, 0)
    print(f"Address: {addr}")

    # Fund the address using Bitcoin Core
    # (from another terminal)
    # docker exec jm-bitcoin-test bitcoin-cli -regtest -rpcuser=test -rpcpassword=test sendtoaddress <addr> 1.0

    # Sync wallet
    await wallet.sync_mixdepth(0)
    balance = await wallet.get_balance(0)
    print(f"Balance: {balance} sats")

    await wallet.close()

asyncio.run(test())
```

## Funding a Test Wallet

```bash
# Get an address from your wallet
ADDR="bcrt1q..." # Your wallet address

# Send coins from Bitcoin Core wallet
docker exec jm-bitcoin-test bitcoin-cli -regtest -rpcuser=test -rpcpassword=test sendtoaddress $ADDR 1.0

# Mine a block to confirm
docker exec jm-bitcoin-test bitcoin-cli -regtest -rpcuser=test -rpcpassword=test -generate 1
```

## Cleanup

```bash
docker-compose down -v
```

## Troubleshooting

### Bitcoin Core not responding

```bash
# Check if Bitcoin Core is running
docker-compose ps

# Check logs
docker-compose logs bitcoin

# Restart if needed
docker-compose restart bitcoin
```

### Connection refused

```bash
# Make sure ports are exposed
docker-compose port bitcoin 18443

# Should show: 0.0.0.0:18443
```

### RPC authentication failed

Check that docker-compose.yml has correct RPC credentials:
- rpcuser=test
- rpcpassword=test
