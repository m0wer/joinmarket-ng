# End-to-End Integration Tests

Complete system tests with all JoinMarket components.

## Quick Start

```bash
# Clean start (IMPORTANT: always use -v to reset blockchain state)
docker compose --profile all down -v

# Start all services (includes neutrino backend)
docker compose --profile all up -d --build

# Wait for services to be ready
echo "Waiting for Bitcoin..."
until docker compose exec -T bitcoin bitcoin-cli -chain=regtest -rpcport=18443 -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null; do
  sleep 2
done
echo "Bitcoin ready"

echo "Waiting for wallet-funder to complete..."
sleep 30

echo "Waiting for Neutrino to sync..."
until curl -s http://localhost:8334/v1/status | grep -q '"synced":true'; do
  sleep 2
done
echo "Neutrino synced"

# Restart makers to ensure they sync latest blockchain state
docker compose restart maker1 maker2
sleep 10  # Wait for makers to resync

# Run tests
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests

# Cleanup
docker compose --profile all down -v
```

## Docker Compose Profiles

The unified `docker-compose.yml` uses profiles to organize services:

| Profile | Services | Use Case |
|---------|----------|----------|
| (default) | bitcoin, miner, directory, orderbook-watcher | Core infrastructure |
| `maker` | + maker | Single maker bot |
| `taker` | + taker | Single taker client |
| `e2e` | + maker1, maker2 | E2E tests (our implementation) |
| `reference` | + tor, jam, maker1, maker2 | Reference JAM compatibility tests |
| `neutrino` | + neutrino, maker-neutrino, taker-neutrino | Light client testing |
| `all` | e2e + reference + neutrino | **Full test suite** |

## Running Tests

### Full Test Suite (Recommended)

Run ALL tests including reference compatibility:

```bash
# Clean start (IMPORTANT!)
docker compose --profile all down -v

# Start all services (includes neutrino)
docker compose --profile all up -d --build

# Wait for Bitcoin to be ready
echo "Waiting for Bitcoin..."
until docker compose exec -T bitcoin bitcoin-cli -chain=regtest -rpcport=18443 -rpcuser=test -rpcpassword=test getblockchaininfo 2>/dev/null; do
  sleep 2
done

# Wait for wallet funding to complete
echo "Waiting for wallet funding..."
sleep 30

# Wait for Neutrino to sync
echo "Waiting for Neutrino..."
until curl -s http://localhost:8334/v1/status | grep -q '"synced":true'; do
  sleep 2
done

# Restart makers to ensure they have latest blockchain state
docker compose restart maker1 maker2
sleep 10

# Run complete test suite
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests

# Cleanup
docker compose --profile all down -v
```

### E2E Tests Only (Faster)

Tests our implementation without reference JAM:

```bash
# Clean start
docker compose --profile e2e down -v

# Start services
docker compose --profile e2e up -d --build
sleep 30  # Wait for wallet funding

# Restart makers
docker compose restart maker1 maker2
sleep 10

# Run tests
pytest tests/e2e/test_complete_system.py -v

# Cleanup
docker compose --profile e2e down -v
```

### Reference Tests Only

Tests compatibility with upstream JoinMarket:

```bash
# Clean start
docker compose --profile reference down -v

# Start services
docker compose --profile reference up -d --build
sleep 30  # Wait for wallet funding

# Restart our makers to ensure they have latest blockchain state
docker compose restart maker1 maker2
sleep 10

# Test our implementation with reference components:
pytest tests/e2e/test_reference_coinjoin.py -v -s       # Reference maker + taker
pytest tests/e2e/test_our_maker_reference_taker.py -v -s # Our maker + reference taker

# Cleanup
docker compose --profile reference down -v
```

### Neutrino Backend Tests

Tests the neutrino light client backend:

```bash
# Clean start
docker compose --profile all down -v

# Start services with neutrino
docker compose --profile all up -d --build
sleep 30

# Wait for neutrino to sync (should happen automatically)
until curl -s http://localhost:8334/v1/status | grep -q '"synced":true'; do
  echo "Waiting for neutrino sync..."
  sleep 5
done

# Run neutrino tests
pytest tests/e2e/test_neutrino_backend.py -v

# Cleanup
docker compose --profile all down -v
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
│  Neutrino Profile:                                                    │
│  ┌──────────────┐                                                     │
│  │   Neutrino   │ ◄── Light client (BIP157/158)                       │
│  │   Server     │                                                     │
│  └──────────────┘                                                     │
│                                                                       │
│  Reference Profile Only:                                              │
│  ┌──────────────┐    ┌──────────────┐                                │
│  │     Tor      │───►│     JAM      │                                │
│  │   (.onion)   │    │  (Reference) │                                │
│  └──────────────┘    └──────────────┘                                │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Pre-Generated Tor Keys

The reference tests use a **deterministic Tor hidden service** for reproducibility:
- Onion address: `tsc2niuqhhnl35q4tzpyyuogcxscgxhotjrk3ldaynfsgysoctlgwxqd.onion`
- Keys stored in: `tests/e2e/reference/tor_keys/`
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
- Tests will fail (not skip) if neutrino is unavailable or not synced

## Troubleshooting

### ⚠️ IMPORTANT: Always Clean Volumes Before Testing

**Docker volumes persist blockchain state between runs.** If you restart services without cleaning volumes, makers will have outdated wallet state and tests will fail with:

```
ERROR: outputs unconfirmed or already spent. utxo_data=[None]
```

**Solution:** Always use `down -v` and restart makers after funding:

```bash
# Clean volumes
docker compose --profile all down -v

# Start fresh
docker compose --profile all up -d --build
sleep 30

# Restart makers to sync latest blockchain
docker compose restart maker1 maker2
sleep 10
```

### Check Service Status

```bash
docker compose --profile all ps
docker compose logs <service-name>
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

Make sure JAM is running:
```bash
docker compose --profile reference ps | grep jam
```

If not running, tests should skip automatically. If they fail instead, check:
```bash
docker compose --profile reference logs jam
```

### Wallet Has Zero Balance

The auto-miner and test fixtures should fund wallets automatically. If needed:

```bash
ADDR="bcrt1q..."
docker compose exec bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 $ADDR
```

## CI/CD

The GitHub Actions workflow runs all tests automatically:

1. **Unit tests**: Each component tested independently
2. **E2E tests**: Full system integration tests
3. **Reference tests**: Compatibility with upstream JoinMarket (main branch only)

See `.github/workflows/test.yaml` for details.

## Security Notes

⚠️ **These are development/test environments only!**

- Never use on mainnet
- Never use real mnemonics
- Never store real funds
- Only for testing on regtest

---

**Status:** E2E tests fully automated ✓
