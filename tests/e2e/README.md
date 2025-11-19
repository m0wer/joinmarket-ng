# End-to-End Integration Tests

Complete system tests with all JoinMarket components.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 JoinMarket System                     │
├──────────────────────────────────────────────────────┤
│                                                       │
│  ┌──────────────┐    ┌──────────────┐               │
│  │   Bitcoin    │◄───│  Directory   │               │
│  │   Regtest    │    │   Server     │               │
│  └──────────────┘    └──────────────┘               │
│         ▲                    ▲                        │
│         │                    │                        │
│         │            ┌───────┴────────┐              │
│         │            │                 │              │
│  ┌──────┴──────┐  ┌─▼──────────┐  ┌──▼────────┐    │
│  │   Wallet    │  │  Orderbook  │  │   Maker   │    │
│  │  Service    │  │   Watcher   │  │    Bot    │    │
│  └─────────────┘  └─────────────┘  └───────────┘    │
│                                                       │
└──────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose
- Python 3.14+
- pytest and pytest-asyncio

## Setup

### 1. Start All Components

```bash
# From repository root
docker-compose up -d

# Wait for services to be healthy (~30 seconds)
docker-compose ps
```

### 2. Verify Services

```bash
# Check Bitcoin Core
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo

# Check Directory Server (should respond)
curl http://localhost:5222

# Check Orderbook Watcher
curl http://localhost:8080
```

### 3. Fund Test Wallet

```bash
# Generate an address
python3 -c "
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
seed = mnemonic_to_seed(mnemonic)
master = HDKey.from_seed(seed)
key = master.derive('m/84\'/0\'/0\'/0/0')
print(key.get_address('regtest'))
"

# Send coins to that address
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test sendtoaddress <ADDRESS> 1.0

# Mine a block
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test -generate 1
```

## Running Tests

### Run All E2E Tests

```bash
# From repository root
pytest tests/e2e/test_complete_system.py -v -s
```

### Run Specific Test

```bash
pytest tests/e2e/test_complete_system.py::test_bitcoin_connection -v
```

### Run With Coverage

```bash
pytest tests/e2e/ -v --cov=jmwallet --cov=maker --cov-report=html
```

## Test Scenarios

### 1. System Health Check

Tests that all services are running and accessible:
- Bitcoin Core regtest node
- Directory server
- Wallet synchronization

```bash
pytest tests/e2e/test_complete_system.py::test_system_health_check -v
```

### 2. Wallet Operations

Tests wallet functionality:
- Address generation
- Balance checking
- UTXO management
- Coin selection

```bash
pytest tests/e2e/test_complete_system.py::test_wallet_sync -v
```

### 3. Maker Bot Initialization

Tests maker bot setup:
- Configuration loading
- Offer creation
- Directory connection

```bash
pytest tests/e2e/test_complete_system.py::test_maker_bot_initialization -v
```

### 4. Offer Creation

Tests offer management:
- Balance-based offer sizing
- Fee calculations
- Offer validation

```bash
pytest tests/e2e/test_complete_system.py::test_offer_creation -v
```

## Manual Testing

### Test Wallet Sync

```python
import asyncio
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService

async def test():
    backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test"
    )

    wallet = WalletService(
        mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        backend=backend,
        network="regtest"
    )

    print("Syncing wallet...")
    await wallet.sync_all()

    print("\nBalances:")
    for md in range(5):
        balance = await wallet.get_balance(md)
        print(f"  Mixdepth {md}: {balance:,} sats")

    total = await wallet.get_total_balance()
    print(f"\nTotal: {total:,} sats")

    await wallet.close()

asyncio.run(test())
```

### Test Maker Bot

```python
import asyncio
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService
from maker.bot import MakerBot
from maker.config import MakerConfig
from jmcore.models import NetworkType

async def test():
    config = MakerConfig(
        mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        network=NetworkType.REGTEST,
        backend_type="bitcoin_core",
        backend_config={
            "rpc_url": "http://127.0.0.1:18443",
            "rpc_user": "test",
            "rpc_password": "test",
        },
        directory_servers=["127.0.0.1:5222"],
    )

    backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test"
    )

    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network="regtest"
    )

    bot = MakerBot(wallet, backend, config)

    print(f"Maker nick: {bot.nick}")

    # Note: bot.start() will run indefinitely
    # For testing, you can manually create offers:
    from maker.offers import OfferManager
    offer_manager = OfferManager(wallet, config, bot.nick)

    await wallet.sync_all()
    offers = await offer_manager.create_offers()

    if offers:
        print(f"\nCreated {len(offers)} offer(s):")
        for offer in offers:
            print(f"  Type: {offer.ordertype}")
            print(f"  Size: {offer.minsize:,} - {offer.maxsize:,} sats")
            print(f"  CJ Fee: {offer.cjfee}")
            print(f"  TX Fee: {offer.txfee:,} sats")
    else:
        print("\nNo offers created (insufficient balance?)")

    await wallet.close()

asyncio.run(test())
```

## Troubleshooting

### Bitcoin Core Not Responding

```bash
# Check logs
docker-compose logs bitcoin

# Restart
docker-compose restart bitcoin

# Wait for sync
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockcount
# Should be > 100
```

### Directory Server Not Responding

```bash
# Check logs
docker-compose logs directory

# Restart
docker-compose restart directory

# Test connection
nc -zv localhost 5222
```

### Wallet Has Zero Balance

```bash
# Check if wallet address has funds
ADDR="bcrt1q..."  # Your address
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test scantxoutset start "[\"addr($ADDR)\"]"

# Send funds if needed
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test sendtoaddress $ADDR 1.0
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test -generate 1
```

### Tests Timing Out

```bash
# Increase pytest timeout
pytest tests/e2e/ -v --timeout=120

# Or run specific test
pytest tests/e2e/test_complete_system.py::test_bitcoin_connection -v
```

## Service URLs

- Bitcoin RPC: http://localhost:18443
- Directory Server: localhost:5222
- Orderbook Watcher: http://localhost:8080

## Cleanup

```bash
# Stop all services
docker-compose down

# Remove all data (including blockchain)
docker-compose down -v
```

## Advanced Testing

### Load Testing

```bash
# Run tests in parallel
pytest tests/e2e/ -v -n 4
```

### Stress Testing

```bash
# Run tests repeatedly
for i in {1..10}; do
    echo "Run $i"
    pytest tests/e2e/test_complete_system.py -v
done
```

### Memory Profiling

```bash
pytest tests/e2e/ -v --memray
```

## CI/CD Integration

```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Start services
        run: docker-compose up -d

      - name: Wait for services
        run: |
          sleep 30
          docker-compose ps

      - name: Run tests
        run: |
          pip install -e jmwallet[dev]
          pip install -e maker[dev]
          pytest tests/e2e/ -v

      - name: Cleanup
        run: docker-compose down -v
```

## Performance Benchmarks

Expected performance on typical hardware:

- Wallet sync (empty): < 5 seconds
- Wallet sync (100 addresses): < 30 seconds
- Offer creation: < 1 second
- Directory connection: < 5 seconds
- PoDLE verification: < 1 second
- Transaction verification: < 1 second

## Security Notes

These are **development/test** environments:
- ⚠️ Never use on mainnet
- ⚠️ Never use real mnemonics
- ⚠️ Never store real funds
- ⚠️ Only for testing on regtest

## Next Steps

After E2E tests pass:
1. Security audit of critical components
2. Extensive testnet testing
3. Performance optimization
4. Production deployment preparation

---

**Status:** E2E tests ready for regtest ✓
**Last Updated:** 2025-01-18
