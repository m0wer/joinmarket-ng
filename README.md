# JoinMarket Refactor

Modern, clean alternative implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/) components following SOLID principles.

## About This Project

This project is an alternative implementation of the reference JoinMarket protocol from [joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver/). The goal is to provide a clean, maintainable, and auditable codebase while maintaining full backwards compatibility with the existing JoinMarket network.

### Key Features

- **No BerkeleyDB Required**: Works with Bitcoin Core v30+ out of the box
- **Neutrino SPV Support**: Run without a full node using BIP157/158 compact block filters
- **Privacy-Preserving**: Tor integration, Neutrino filters never reveal your addresses
- **Modern Stack**: Python 3.14+, Pydantic v2, AsyncIO, Go (for Neutrino server)

### Goals

- **Clean Code**: Easy to understand, review, and audit
- **Maintainability**: SOLID principles, modern Python patterns, comprehensive tests
- **Security**: Isolated architecture, minimal attack surface, security-first design
- **Performance**: Optimized for low latency and high throughput
- **Auditability**: Clear separation of concerns, well-documented code

### Roadmap

We are incrementally implementing JoinMarket components while maintaining protocol compatibility:

| Phase | Component | Status | Description |
|-------|-----------|--------|-------------|
| 1 | **jmcore** | ✅ Complete | Protocol definitions, crypto primitives, shared models |
| 2 | **Directory Server** | ✅ Complete | Peer discovery and message routing relay |
| 3 | **Orderbook Watcher** | ✅ Complete | Monitor and aggregate CoinJoin orders |
| 4 | **jmwallet** | ✅ Complete | BIP32/39/84 wallet with pluggable backends (NO BerkeleyDB!) |
| 5 | **Maker Bot** | ✅ Complete | Yield generator - PoDLE, TX verification, signing, fidelity bonds |
| 6 | **Taker Bot** | 🚧 In Progress | CoinJoin participant |
| 7 | **Neutrino Server** | ✅ Complete | Lightweight SPV backend (BIP157/158) |
| 8 | **Protocol Extensions** | 🔮 Future | Nostr relays, [CoinJoinXT](https://www.youtube.com/watch?v=YS0MksuMl9k) + LN |

**Maker Bot Status (Phase 5):**
- ✅ PoDLE verification (anti-sybil)
- ✅ Transaction verification (prevents fund loss)
- ✅ CoinJoin protocol handler
- ✅ Offer management
- ✅ Transaction signing
- ✅ Fidelity bonds
- ✅ CLI interface

All components maintain backwards compatibility with the reference implementation.

## Project Structure

```
jm-refactor/
├── jmcore/              # Shared library for all JoinMarket components
│   ├── src/jmcore/      # Core protocol, crypto, and messaging primitives
│   └── tests/           # Tests for shared library
├── jmwallet/            # Wallet library with pluggable backends
│   ├── src/jmwallet/    # BIP32/39/84 implementation
│   └── tests/           # Wallet tests
├── directory_server/    # Directory/relay server implementation
│   ├── src/             # Server implementation
│   ├── tests/           # Server tests
│   └── docker/          # Dockerfile and configs
├── orderbook_watcher/   # Orderbook aggregation and monitoring
│   ├── src/             # Watcher implementation
│   ├── static/          # Web UI
│   └── tests/           # Watcher tests
├── maker/               # Maker bot (yield generator)
│   ├── src/maker/       # Bot implementation
│   └── tests/           # Integration and E2E tests
├── neutrino_server/     # Lightweight SPV server (Go)
│   ├── cmd/neutrinod/   # Server entry point
│   └── internal/        # API and neutrino node wrapper
└── tests/               # Repository-level E2E tests
```

## Components

### jmcore - Shared Library

Core functionality shared across JoinMarket components:

- Message protocol definitions and serialization
- Cryptographic primitives (encryption, signing)
- Network primitives (Tor integration, connection management)
- Common models and types

### Directory Server

Onion-based relay server for peer discovery and message routing:

- Tor hidden service for privacy
- Peer registration and discovery
- Message forwarding (public broadcast, private routing)
- Connection management

### Orderbook Watcher

Real-time orderbook aggregation and monitoring service:

- Connects to directory servers to monitor CoinJoin offers
- Aggregates and validates orders from makers
- Bond verification and validation
- Web-based dashboard for market visibility

### jmwallet - Wallet Library

Modern Bitcoin wallet library with NO BerkeleyDB dependency:

- BIP32/39/84 hierarchical deterministic wallets
- JoinMarket mixdepth support (5 isolation levels)
- Pluggable blockchain backends:
  - **Bitcoin Core**: Full node via RPC (most secure, requires running node)
  - **Neutrino**: Lightweight BIP157/BIP158 SPV client (privacy-preserving, low resource)
- Works with Bitcoin Core v30+ (no deprecated BDB wallet!)

### Maker Bot

Yield generator / liquidity provider bot:

- Connects to directory servers
- Announces liquidity offers
- Handles CoinJoin protocol with takers
- PoDLE verification (anti-sybil)
- Transaction verification (prevents loss of funds)
- Fidelity bond support

### Neutrino Server

Lightweight SPV server using BIP157/158 compact block filters:

- **No full node required**: ~500MB storage vs ~500GB for Bitcoin Core
- **Privacy-preserving**: Downloads filters, not addresses (unlike Bloom filters)
- **Fast sync**: Minutes instead of days
- **Written in Go**: Wraps lightninglabs/neutrino library
- **REST API**: Simple HTTP interface for wallet integration

## Development Philosophy

- **SOLID Principles**: Clean architecture with clear separation of concerns
- **Type Safety**: Full Pydantic models and type hints
- **Modern Python**: Python 3.14+ features, async/await where beneficial
- **Performance**: Optimized for low latency and high throughput
- **Observability**: Structured logging with loguru
- **Testability**: High test coverage with pytest
- **Code Quality**: Pre-commit hooks with ruff for linting and formatting

See more at [DOCS.md](./DOCS.md).

## 🌟 Key Innovation: Neutrino SPV Support

Run JoinMarket without a full Bitcoin node! Our Neutrino implementation uses BIP157/158 compact block filters for privacy-preserving light client operation.

```bash
# Start with Neutrino backend (downloads block filters, ~500MB vs ~500GB for full node)
docker-compose --profile neutrino up -d

# This starts:
# - Neutrino server (BIP157/158 compact block filters)
# - Maker with Neutrino backend
# - Taker with Neutrino backend
```

**Why Neutrino over traditional SPV?**

| Feature | Full Node | Bloom Filter SPV | Neutrino SPV |
|---------|-----------|------------------|--------------|
| Storage | ~500 GB | ~50 MB | ~500 MB |
| Initial Sync | Days | Minutes | Minutes |
| Privacy | Full | **Low** (reveals addresses) | **High** (downloads all filters) |
| Validation | Full | Headers only | Headers + filters |

**When to use Bitcoin Core instead:**
- Maximum security (full validation)
- You already run a full node
- Production deployments with high value

## 🎯 Key Innovation: No BerkeleyDB Dependency!

**The Problem:**
```
Reference JoinMarket: Requires Bitcoin Core wallet with BerkeleyDB
→ Bitcoin Core v30 removed BDB support
→ Requires deprecatedrpc=create_bdb workaround
→ Broken for new users!
```

**Our Solution:**
```
jmwallet: Uses scantxoutset RPC directly (no wallet needed!)
→ Works with Bitcoin Core v30+ out of the box
→ Also supports Mempool.space API (zero setup!)
→ Beginner-friendly AND privacy-preserving
```

## Quick Start

> **WARNING: This is experimental software. Use at your own risk!**
>
> - **DO NOT use with significant funds** until the software has been extensively audited
> - **Always start with small amounts** on testnet or regtest before mainnet
> - **Back up your mnemonic phrase** securely - it's the only way to recover funds
> - **Use Tor** for all directory server connections on mainnet

### Run Complete System

```bash
# Start all services (Bitcoin, Directory, Orderbook Watcher)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Using Neutrino (Lightweight SPV)

For a lightweight setup without running a full Bitcoin node:

```bash
# Start with Neutrino backend (downloads block filters, ~500MB vs ~500GB for full node)
docker-compose --profile neutrino up -d

# This starts:
# - Neutrino server (BIP157/158 compact block filters)
# - Maker with Neutrino backend
# - Taker with Neutrino backend
```

**Benefits of Neutrino:**
- No full node required (~500MB vs ~500GB storage)
- Privacy-preserving (downloads filters, not addresses)
- Low bandwidth usage
- Fast initial sync (minutes vs days)

**When to use Bitcoin Core instead:**
- Maximum security (full validation)
- You already run a full node
- Production deployments with high value

### Test Wallet Library

```python
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService

# Create wallet (works with Bitcoin Core v30+!)
backend = BitcoinCoreBackend(
    rpc_url="http://127.0.0.1:18443",
    rpc_user="test",
    rpc_password="test"
)

wallet = WalletService(
    mnemonic="your mnemonic here",
    backend=backend,
    network="regtest"
)

# Sync and check balance (no BDB wallet needed!)
await wallet.sync_all()
balance = await wallet.get_total_balance()
print(f"Balance: {balance:,} sats")
```

### Using Neutrino Backend

```python
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig
from jmwallet.wallet.service import WalletService

# Configure Neutrino (connects to lightweight SPV server)
config = NeutrinoConfig(
    base_url="http://localhost:8080",
    network="mainnet"
)
backend = NeutrinoBackend(config)

wallet = WalletService(
    mnemonic="your mnemonic here",
    backend=backend,
    network="mainnet"
)

# Same API as Bitcoin Core backend
await wallet.sync_all()
balance = await wallet.get_total_balance()
```

## Getting Started

See individual component READMEs for detailed instructions:

- [jmcore](./jmcore/README.md) - Core library
- [jmwallet](./jmwallet/) - Wallet library
- [Directory Server](./directory_server/README.md) - Message relay
- [Orderbook Watcher](./orderbook_watcher/README.md) - Market monitoring
- [Maker Bot](./maker/README.md) - Yield generator
- [Taker Bot](./taker/README.md) - CoinJoin participant
- [E2E Tests](./tests/e2e/README.md) - Complete system tests
- [Protocol & Architecture Documentation](./DOCS.md) - Full technical documentation

## Development

### Dependency Management

This project uses [pip-tools](https://github.com/jazzband/pip-tools) to pin dependencies for reproducible builds and security.

```bash
# Install pip-tools
pip install pip-tools

# Update pinned dependencies (run this after changing pyproject.toml)
# In jmcore:
cd jmcore
python -m piptools compile -Uv pyproject.toml -o requirements.txt

# In directory_server (uses requirements.in for local jmcore dependency):
cd directory_server
python -m piptools compile -Uv requirements.in -o requirements.txt
```

**Note**: The directory_server uses a `requirements.in` file to properly handle the local jmcore dependency with `-e ../jmcore`. The pinned `requirements.txt` files are used in Docker builds for reproducible deployments.

## Running Tests with Docker Compose

To run the end-to-end tests against a running docker compose stack:

1. Start the services:
   ```bash
   docker compose up -d bitcoin directory
   ```

2. Run the tests:
   ```bash
   pytest tests/e2e/test_complete_system.py -v -s
   ```

The tests will automatically detect the running directory server on port 5222 and use it.

## Security Considerations

### Before Using with Real Funds

1. **Backup your mnemonic phrase** - Store it securely offline. This is the ONLY way to recover funds.

2. **Start on testnet/regtest** - Test all operations with test coins before using real bitcoin.

3. **Use Tor** - Always connect to directory servers over Tor on mainnet for privacy.

4. **Verify transaction details** - The maker bot verifies all transactions automatically, but always review logs.

5. **Set conservative fees** - Start with higher maker fees to account for transaction fee fluctuations.

6. **Monitor your bot** - Check logs regularly for any errors or suspicious activity.

### Mainnet Configuration Checklist

```bash
# Required environment variables for mainnet:
export NETWORK=mainnet
export MNEMONIC="your secure 12/24 word mnemonic"  # NEVER commit this!
export BITCOIN_RPC_URL=http://localhost:8332
export BITCOIN_RPC_USER=your_rpc_user
export BITCOIN_RPC_PASSWORD=your_secure_password

# Recommended directory servers (mainnet)
# Connect via Tor - these are onion addresses
export DIRECTORY_SERVERS=directory1.onion:5222,directory2.onion:5222

# Enable Tor (required for mainnet privacy)
export TOR_SOCKS_HOST=127.0.0.1
export TOR_SOCKS_PORT=9050
```

### Critical Security Code

The following modules are security-critical and have been designed to prevent loss of funds:

| Module | Purpose | Test Coverage |
|--------|---------|---------------|
| `maker/tx_verification.py` | Verifies CoinJoin transactions before signing | 100% |
| `jmwallet/wallet/signing.py` | Transaction signing | 95% |
| `jmcore/podle.py` | Anti-sybil proof verification | 90%+ |

## License

MIT License. See [LICENSE](./LICENSE) for details.
