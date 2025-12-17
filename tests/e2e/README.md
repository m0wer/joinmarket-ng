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

# Mine blocks to that address (110 blocks for coinbase maturity)
# Note: On regtest, mining to an address funds it with the coinbase reward (50 BTC)
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 <ADDRESS>
```

## Running Tests

### Run All E2E Tests

```bash
# From repository root
pytest tests/e2e/test_complete_system.py -v -s
```

### Run With Different Backends

```bash
# Default: Bitcoin Core backend
pytest tests/e2e/ -v

# Explicitly use Bitcoin Core
pytest tests/e2e/ -v --backend=bitcoin_core

# Use Neutrino backend (requires neutrino server running)
pytest tests/e2e/ -v --backend=neutrino --neutrino-url=http://127.0.0.1:8334

# Run with both backends (where applicable)
pytest tests/e2e/ -v --backend=all
```

### Run Specific Test

```bash
pytest tests/e2e/test_complete_system.py::test_bitcoin_connection -v
```

### Run With Coverage

```bash
pytest tests/e2e/ -v --cov=jmwallet --cov=maker --cov-report=html
```

## Backend Configuration

### Bitcoin Core (Default)

Uses Bitcoin Core RPC for full node validation:

```bash
# Environment variables (or defaults)
export BITCOIN_RPC_URL="http://127.0.0.1:18443"
export BITCOIN_RPC_USER="test"
export BITCOIN_RPC_PASSWORD="test"

pytest tests/e2e/ -v --backend=bitcoin_core
```

### Neutrino (Lightweight)

Uses Neutrino BIP157/158 light client:

```bash
# Start neutrino server first
docker-compose --profile neutrino up -d neutrino

# Run tests with neutrino
export NEUTRINO_URL="http://127.0.0.1:8334"
pytest tests/e2e/ -v --backend=neutrino
```

**Note:** Neutrino on regtest requires connecting to the Bitcoin Core node as a peer:
```bash
# In docker-compose.yml, neutrino connects to bitcoin:18444
docker-compose --profile neutrino up -d
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

### 5. Taker Tests

Tests taker functionality:
- Taker initialization and nick generation
- Directory server connection
- Orderbook fetching
- PoDLE commitment generation
- Transaction builder utilities

```bash
# Run all taker tests
pytest tests/e2e/test_complete_system.py -k "taker" -v

# Run specific taker tests
pytest tests/e2e/test_complete_system.py::test_taker_initialization -v
pytest tests/e2e/test_complete_system.py::test_taker_connect_directory -v
pytest tests/e2e/test_complete_system.py::test_taker_orderbook_fetch -v
pytest tests/e2e/test_complete_system.py::test_taker_orderbook_manager -v
pytest tests/e2e/test_complete_system.py::test_taker_podle_generation -v
pytest tests/e2e/test_complete_system.py::test_taker_tx_builder -v
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

# Mine directly to the address to fund it (coinbase reward)
docker exec jm-bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 $ADDR
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

---

## Reference Implementation Testing

Tests our components against the reference JoinMarket implementation (jam-standalone).

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     Reference Implementation Test                   │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│  │   Bitcoin    │◄───│  Directory   │◄───│     Tor      │         │
│  │   Regtest    │    │   Server     │    │   (Hidden    │         │
│  └──────────────┘    │  (Our impl)  │    │   Service)   │         │
│         ▲            └──────────────┘    └──────────────┘         │
│         │                    ▲                    ▲                 │
│         │                    │                    │                 │
│         │            ┌───────┴────────┐          │                 │
│         │            │                 │          │                 │
│  ┌──────┴──────┐  ┌─▼──────────┐  ┌──▼────────┐ │                 │
│  │   Maker 1   │  │  Maker 2   │  │    JAM     │◄┘                 │
│  │ (Our impl)  │  │ (Our impl) │  │ (Reference │                   │
│  └─────────────┘  └────────────┘  │   Taker)   │                   │
│                                    └────────────┘                   │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

### Prerequisites

- Docker and Docker Compose
- The jam-standalone image uses an internal Tor daemon
- Our directory server is exposed via a Tor hidden service

### Setup

#### 1. Start Reference Test Services

```bash
# From repository root
docker compose -f docker-compose.reference.yml up -d

# Wait for services to be healthy (~2 minutes for Tor)
docker compose -f docker-compose.reference.yml ps
```

#### 2. Get the Tor Hidden Service Address

```bash
# Wait ~30 seconds for Tor to generate the onion address
docker compose -f docker-compose.reference.yml exec tor \
    cat /var/lib/tor/hidden_service/directory/hostname
```

#### 3. Update JAM Configuration

Edit `tests/e2e/reference/joinmarket.cfg` and replace the `directory_nodes` placeholder:

```ini
directory_nodes = <your-onion-address>.onion:5222
```

#### 4. Restart JAM to Pick Up Config

```bash
docker compose -f docker-compose.reference.yml restart jam
```

#### 5. Create and Fund JAM Wallet

**Option A: Automated (via expect script)**

The test suite includes an expect script that automates wallet creation:

```bash
# Run the automated test which handles wallet creation
pytest tests/e2e/test_reference_coinjoin.py::test_complete_reference_coinjoin -v -s

# Or manually run the expect script inside the container
docker compose -f docker-compose.reference.yml exec jam \
    expect /scripts/create_wallet.exp testpassword123 test_wallet.jmdat
```

**Option B: Manual (interactive prompts)**

```bash
# Enter jam container
docker compose -f docker-compose.reference.yml exec jam bash

# Generate wallet (follow interactive prompts)
python /src/scripts/wallet-tool.py --datadir=/root/.joinmarket generate

# Display wallet and get an address
python /src/scripts/wallet-tool.py --datadir=/root/.joinmarket \
    /root/.joinmarket/wallets/wallet.jmdat

# Exit container
exit

# Fund the wallet (mine blocks to the address)
docker compose -f docker-compose.reference.yml exec bitcoin \
    bitcoin-cli -regtest -rpcuser=test -rpcpassword=test \
    generatetoaddress 111 <wallet-address>
```

#### 6. Fund Our Maker Wallets

The makers will auto-fund when they start, but you can also fund them manually:

```bash
# Check maker logs for their addresses
docker compose -f docker-compose.reference.yml logs maker1 | grep -i address
docker compose -f docker-compose.reference.yml logs maker2 | grep -i address
```

### Running the CoinJoin

Once all wallets are funded and connected:

```bash
# Enter jam container
docker compose -f docker-compose.reference.yml exec jam bash

# Get a destination address (from mixdepth 1)
python /src/scripts/wallet-tool.py --datadir=/root/.joinmarket \
    /root/.joinmarket/wallets/wallet.jmdat

# Run the coinjoin (0.1 BTC, 2 makers, from mixdepth 0)
python /src/scripts/sendpayment.py --datadir=/root/.joinmarket \
    -N 2 -m 0 /root/.joinmarket/wallets/wallet.jmdat 0.1btc <destination-address>
```

### Running Automated Tests

```bash
# Run all reference implementation tests
pytest tests/e2e/test_reference_coinjoin.py -v -s --timeout=600

# Run just the service health check
pytest tests/e2e/test_reference_coinjoin.py::test_services_healthy -v

# Run the complete coinjoin setup test (creates wallet, funds it)
pytest tests/e2e/test_reference_coinjoin.py::test_complete_reference_coinjoin -v -s

# Run the full coinjoin execution test (skipped by default)
pytest tests/e2e/test_reference_coinjoin.py::test_execute_reference_coinjoin -v -s --no-skip
```

### Troubleshooting

#### JAM Can't Connect to Directory

```bash
# Check Tor hidden service is running
docker compose -f docker-compose.reference.yml exec tor \
    cat /var/lib/tor/hidden_service/directory/hostname

# Check JAM logs
docker compose -f docker-compose.reference.yml logs jam

# Check directory server logs
docker compose -f docker-compose.reference.yml logs directory
```

#### Makers Not Showing in Orderbook

```bash
# Check maker logs
docker compose -f docker-compose.reference.yml logs maker1
docker compose -f docker-compose.reference.yml logs maker2

# Check directory server for connected peers
docker compose -f docker-compose.reference.yml logs directory | grep -i peer
```

#### Protocol Compatibility Issues

The reference implementation expects:
- JoinMarket protocol version 5
- Onion-based messaging (port 5222)
- Specific message format with `!` prefix commands

Our implementation should be compatible, but check:
- Message format in directory server logs
- Protocol version in handshake

### Cleanup

```bash
# Stop all reference test services
docker compose -f docker-compose.reference.yml down

# Remove volumes (clears all data)
docker compose -f docker-compose.reference.yml down -v
```

### Notes

- The jam-standalone image contains Tor internally
- Our directory is exposed via Tor hidden service on port 5222
- This tests real protocol compatibility, not just unit behavior
- CoinJoin completion typically takes 1-5 minutes
