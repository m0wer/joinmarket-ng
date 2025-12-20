# End-to-End Integration Tests

Complete system tests with all JoinMarket components.

## Quick Start

```bash
# Start services for your test scenario (pick one)
docker compose --profile e2e up -d --build      # Our implementation only
docker compose --profile reference up -d --build # Reference compatibility
docker compose --profile neutrino up -d --build  # Neutrino backend

# Wait for services
sleep 30

# Run relevant tests
pytest tests/e2e -v

# Cleanup
docker compose --profile <your-profile> down -v
```

## Docker Compose Profiles

The unified `docker-compose.yml` uses profiles to organize services:

| Profile | Services | Use Case |
|---------|----------|----------|
| (default) | bitcoin, miner, directory, orderbook-watcher | Core infrastructure |
| `maker` | + maker | Single maker bot |
| `taker` | + taker | Single taker client |
| `e2e` | + maker1, maker2, wallet-funder | E2E tests (our implementation) |
| `reference` | + tor, jam, bitcoin-jam, maker1, maker2 | Reference JAM compatibility |
| `neutrino` | + neutrino, maker-neutrino, wallet-funder | Light client testing |
| `reference-maker` | + jam-maker1, jam-maker2 | Reference makers (rarely needed) |

### Important: Don't Mix Neutrino with Reference

The `neutrino` and `reference` profiles should NOT be run together because:

1. The **neutrino maker** advertises offers to the directory server
2. The **reference taker (JAM)** may pick up these offers
3. But neutrino connects to the main `bitcoin` node, while JAM's wallet is on `bitcoin-jam`
4. Result: neutrino maker can't verify JAM's UTXOs and the coinjoin fails

**If you previously ran `--profile all`, stop the neutrino maker first:**

```bash
docker stop jm-maker-neutrino
```

## Test Suites

### 1. E2E Tests (Our Implementation)

Tests our maker/taker implementation without any reference components.

```bash
# Clean start
docker compose --profile e2e down -v

# Start services
docker compose --profile e2e up -d --build

# Wait for services
echo "Waiting for Bitcoin..."
until docker compose exec -T bitcoin bitcoin-cli -chain=regtest \
    -rpcport=18443 -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null; do
  sleep 2
done

echo "Waiting for wallet funding..."
sleep 30

# Restart makers to sync latest blockchain state
docker compose restart maker1 maker2
sleep 10

# Run tests
pytest tests/e2e/test_complete_system.py -v -s

# Cleanup
docker compose --profile e2e down -v
```

### 2. Reference Compatibility Tests

Tests our makers with the reference JoinMarket taker (JAM).

```bash
# Clean start
docker compose --profile reference down -v

# Start services (includes Tor for onion routing)
docker compose --profile reference up -d --build

# Wait for Bitcoin
echo "Waiting for Bitcoin..."
until docker compose exec -T bitcoin bitcoin-cli -chain=regtest \
    -rpcport=18443 -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null; do
  sleep 2
done

# Wait for Tor hidden service
echo "Waiting for Tor..."
until docker compose exec -T tor cat /var/lib/tor/directory/hostname 2>/dev/null | grep -q ".onion"; do
  sleep 2
done

echo "Waiting for wallet funding and JAM startup..."
sleep 60

# Restart makers to sync latest blockchain state
docker compose restart maker1 maker2
sleep 20

# Run reference tests
pytest tests/e2e/test_reference_coinjoin.py tests/e2e/test_our_maker_reference_taker.py -v -s

# Cleanup
docker compose --profile reference down -v
```

### 3. Neutrino Backend Tests

Tests the BIP157/158 light client backend.

```bash
# Clean start
docker compose --profile neutrino down -v

# Start services
docker compose --profile neutrino up -d --build

# Wait for Bitcoin
echo "Waiting for Bitcoin..."
until docker compose exec -T bitcoin bitcoin-cli -chain=regtest \
    -rpcport=18443 -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null; do
  sleep 2
done

# Wait for Neutrino to sync
echo "Waiting for Neutrino..."
until curl -s http://localhost:8334/v1/status 2>/dev/null | grep -q '"synced":true'; do
  echo "  Neutrino syncing..."
  sleep 5
done
echo "Neutrino synced!"

# Run neutrino tests
pytest tests/e2e/test_neutrino_backend.py -v -s

# Cleanup
docker compose --profile neutrino down -v
```

### 4. Full Test Suite (All Unit + Integration)

Run all tests including unit tests for each component:

```bash
# Start e2e profile for integration tests
docker compose --profile e2e down -v
docker compose --profile e2e up -d --build
sleep 30
docker compose restart maker1 maker2
sleep 10

# Run complete test suite
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests/e2e/test_complete_system.py

# Cleanup
docker compose --profile e2e down -v
```

## Running Specific Tests

```bash
# Single test file
pytest tests/e2e/test_complete_system.py -v

# Single test function
pytest tests/e2e/test_reference_coinjoin.py::test_execute_reference_coinjoin -v -s

# With timeout override
pytest tests/e2e/test_reference_coinjoin.py -v --timeout=600

# Skip slow tests
pytest tests/e2e -v -m "not slow"
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     JoinMarket Test System                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
│  │   Bitcoin    │◄───│  Directory   │◄───│   Orderbook  │            │
│  │   Regtest    │    │   Server     │    │   Watcher    │            │
│  └──────────────┘    └──────────────┘    └──────────────┘            │
│         ▲                    ▲                                        │
│         │            ┌───────┴────────┐                               │
│         │            │                 │                               │
│  ┌──────┴──────┐  ┌─▼──────────┐  ┌──▼────────┐                       │
│  │   Miner     │  │  Maker 1   │  │  Maker 2  │                       │
│  │  (auto)     │  └────────────┘  └───────────┘                       │
│  └─────────────┘                                                      │
│                                                                       │
│  Neutrino Profile (run separately!):                                  │
│  ┌──────────────┐    ┌──────────────────┐                             │
│  │   Neutrino   │◄───│  Maker-Neutrino  │                             │
│  │   Server     │    │  (light client)  │                             │
│  └──────────────┘    └──────────────────┘                             │
│                                                                       │
│  Reference Profile (run separately!):                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
│  │ Bitcoin-JAM  │◄───│     Tor      │───►│     JAM      │            │
│  │  (legacy)    │    │   (.onion)   │    │  (Reference) │            │
│  └──────────────┘    └──────────────┘    └──────────────┘            │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Pre-Generated Tor Keys

The reference tests use a **deterministic Tor hidden service** for reproducibility:
- Onion address: `5x6tavdaf6mdvckxw3jmobxmzxqnnsj3uldro5tvdlvo5hebhureysad.onion`
- Keys stored in: `tests/e2e/reference/tor/data/directory/`
- No dynamic configuration needed!

## Test Wallets

Pre-configured test wallet mnemonics (regtest only!):

| Wallet | Mnemonic |
|--------|----------|
| Maker 1 | `avoid whisper mesh corn already blur sudden fine planet chicken hover sniff` |
| Maker 2 | `minute faint grape plate stock mercy tent world space opera apple rocket` |
| Taker | `burden notable love elephant orbit couch message galaxy elevator exile drop toilet` |
| Generic | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |

## Service URLs

| Service | URL |
|---------|-----|
| Bitcoin RPC | http://localhost:18443 |
| Bitcoin-JAM RPC | http://localhost:18445 (reference profile) |
| Directory Server | localhost:5222 |
| Orderbook Watcher | http://localhost:8080 |
| Neutrino API | http://localhost:8334 |

## Neutrino Backend

The neutrino backend is a BIP157/BIP158 light client that syncs with Bitcoin Core using compact block filters. This provides privacy-preserving SPV operation without downloading the full blockchain.

### Neutrino Status API

Check neutrino sync status:
```bash
curl -s http://localhost:8334/v1/status
# {"synced":true,"block_height":5490,"filter_height":5490,"peers":1}
```

### How Neutrino Works

1. **Compact Block Filters**: Neutrino downloads compact block filters (BIP158) instead of full blocks
2. **Privacy**: Doesn't reveal which addresses you're interested in to peers
3. **Sync**: Syncs headers and filters before reporting as synced
4. **UTXO Discovery**: Uses filter matching to find relevant transactions

### Neutrino Test Requirements

- Bitcoin Core must have `blockfilterindex=1` and `peerblockfilters=1` enabled
- Neutrino needs P2P access to Bitcoin Core on port 18444
- Tests will skip if neutrino is unavailable or not synced

## Troubleshooting

### IMPORTANT: Always Clean Volumes Before Testing

**Docker volumes persist blockchain state between runs.** If you restart services without cleaning volumes, makers will have outdated wallet state and tests will fail with:

```
ERROR: outputs unconfirmed or already spent. utxo_data=[None]
```

**Solution:** Always use `down -v` and restart makers after funding:

```bash
# Clean volumes
docker compose --profile <profile> down -v

# Start fresh
docker compose --profile <profile> up -d --build
sleep 30

# Restart makers to sync latest blockchain
docker compose restart maker1 maker2
sleep 10
```

### Neutrino Maker Interfering with Reference Tests

If reference tests fail with "Makers who didnt respond" or "UTXO not found":

```bash
# Check if neutrino maker is running
docker ps | grep neutrino

# Stop it
docker stop jm-maker-neutrino

# Re-run reference tests
pytest tests/e2e/test_reference_coinjoin.py -v -s
```

The issue is that the neutrino maker can't verify UTXOs from the `bitcoin-jam` node.

### Check Service Status

```bash
docker compose --profile <profile> ps
docker compose logs <service-name>
docker compose logs --tail=50 maker1
```

### Neutrino Not Syncing?

1. Check if Bitcoin Core has block filters enabled:
```bash
docker compose exec bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test getblockchaininfo | grep -A5 filter
```

2. Check neutrino logs:
```bash
docker compose logs neutrino
```

3. Verify neutrino can reach Bitcoin:
```bash
docker compose exec neutrino ping -c 3 jm-bitcoin
```

4. Clear neutrino data and restart:
```bash
docker compose stop neutrino
docker volume rm jm-refactor_neutrino-data
docker compose up -d neutrino
```

### Makers Not Seeing UTXOs?

Check if makers synced after wallet funding:

```bash
# Check maker1 balance
docker compose logs maker1 | grep "Total balance"

# Should show ~5900 BTC. If showing old balance, restart:
docker compose restart maker1 maker2
```

### Reference Tests Failing?

1. Make sure JAM is running:
```bash
docker compose --profile reference ps | grep jam
```

2. Check JAM logs:
```bash
docker compose logs jam --tail=100
```

3. Check Tor is bootstrapped:
```bash
docker compose logs tor | grep -i bootstrap
```

4. Verify our makers see the directory:
```bash
docker compose logs maker1 | grep -i "connected\|handshake"
```

### Wallet Has Zero Balance

The auto-miner and test fixtures should fund wallets automatically. If needed:

```bash
ADDR="bcrt1q..."
docker compose exec bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 $ADDR
```

## CI/CD

The GitHub Actions workflow runs tests in separate jobs:

| Job | Profile | Tests |
|-----|---------|-------|
| `test-e2e` | `e2e` | `test_complete_system.py` |
| `test-reference` | `reference` | `test_reference_coinjoin.py`, `test_our_maker_reference_taker.py` |
| `test-neutrino` | `neutrino` | `test_neutrino_backend.py` |

This separation ensures profiles don't interfere with each other.

See `.github/workflows/test.yaml` for details.

## Security Notes

**These are development/test environments only!**

- Never use on mainnet
- Never use real mnemonics
- Never store real funds
- Only for testing on regtest

---

**Status:** E2E tests fully automated
