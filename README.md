# JoinMarket Refactor

Modern, clean alternative implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/) components following SOLID principles.

## About This Project

This project is an alternative implementation of the reference JoinMarket protocol from [joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver/). The goal is to provide a clean, maintainable, and auditable codebase while maintaining full backwards compatibility with the existing JoinMarket network.

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
| 6 | **Taker Bot** | 📋 Planned | CoinJoin participant |
| 7 | **Protocol Extensions** | 🔮 Future | Nostr relays, [CoinJoinXT](https://www.youtube.com/watch?v=YS0MksuMl9k) + LN |

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
- Pluggable blockchain backends (Mempool, Bitcoin Core, Electrum)
- Works with Bitcoin Core v30+ (no deprecated BDB wallet!)

### Maker Bot

Yield generator / liquidity provider bot:

- Connects to directory servers
- Announces liquidity offers
- Handles CoinJoin protocol with takers
- PoDLE verification (anti-sybil)
- Transaction verification (prevents loss of funds)
- Fidelity bond support

## Development Philosophy

- **SOLID Principles**: Clean architecture with clear separation of concerns
- **Type Safety**: Full Pydantic models and type hints
- **Modern Python**: Python 3.14+ features, async/await where beneficial
- **Performance**: Optimized for low latency and high throughput
- **Observability**: Structured logging with loguru
- **Testability**: High test coverage with pytest
- **Code Quality**: Pre-commit hooks with ruff for linting and formatting

See more at [ARCHITECTURE.md](./ARCHITECTURE.md).

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

### Run Complete System

```bash
# Start all services (Bitcoin, Directory, Orderbook Watcher)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

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

## Getting Started

See individual component READMEs for detailed instructions:

- [jmcore](./jmcore/README.md) - Core library
- [jmwallet](./jmwallet/) - Wallet library
- [Directory Server](./directory_server/README.md) - Message relay
- [Orderbook Watcher](./orderbook_watcher/README.md) - Market monitoring
- [Maker Bot](./maker/README.md) - Yield generator
- [E2E Tests](./tests/e2e/README.md) - Complete system tests
- [Protocol Spec](./docs/PROTOCOL.md) - JoinMarket messaging protocol
- [Architecture](./ARCHITECTURE.md) - Design principles and components
- [Status](./docs/STATUS.md) - Implementation progress and roadmap

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

## License

MIT License. See [LICENSE](./LICENSE) for details.
