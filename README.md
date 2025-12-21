# JoinMarket Refactor

Modern, clean alternative implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/) components.

## About This Project

This project is an alternative implementation of the reference JoinMarket protocol from [joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver/). The goal is to provide a clean, maintainable, and auditable codebase while maintaining full backwards compatibility with the existing JoinMarket network.

### Key Features

- **No BerkeleyDB Required**: Works with Bitcoin Core v30+ out of the box
- **Neutrino SPV Support**: Run without a full node using BIP157/158 compact block filters
- **Privacy-Preserving**: Tor integration, Neutrino filters never reveal your addresses
- **Modern Stack**: Python 3.14+, Pydantic v2, AsyncIO

### Goals

- **Clean Code**: Easy to understand, review, and audit
- **Maintainability**: SOLID principles, modern Python patterns, comprehensive tests
- **Security**: Isolated architecture, minimal attack surface, security-first design
- **Performance**: Optimized for low latency and high throughput
- **Auditability**: Clear separation of concerns, well-documented code

### Roadmap

All components are fully implemented. Future work will focus on improvements, optimizations, and protocol extensions:

- Nostr relays for offer broadcasting
- CoinJoinXT and Lightning Network integration: https://www.youtube.com/watch?v=YS0MksuMl9k

All components maintain backwards compatibility with the reference implementation.

## Project Structure

```
jm-refactor/
├── jmcore/              # Shared library for all JoinMarket components
├── jmwallet/            # Wallet library with pluggable backends
├── directory_server/    # Directory/relay server implementation
├── orderbook_watcher/   # Orderbook aggregation and monitoring
├── maker/               # Maker bot (yield generator)
├── taker/               # Taker bot (CoinJoin orchestrator)
├── (external)           # Neutrino server: https://github.com/m0wer/neutrino-api
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

### Maker Bot

Yield generator / liquidity provider bot:

- Connects to directory servers
- Announces liquidity offers
- Handles CoinJoin protocol with takers
- PoDLE verification (anti-sybil)
- Transaction verification (prevents loss of funds)
- Fidelity bond support

### Taker Script

CoinJoin orchestrator / taker bot:

- Connects to directory servers
- Discovers and selects maker offers
- Initiates CoinJoin transactions
- Manages transaction signing and broadcasting

### Neutrino Server (External)

Lightweight SPV server using BIP157/158 compact block filters.
**Maintained separately at [github.com/m0wer/neutrino-api](https://github.com/m0wer/neutrino-api)**.

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

## Docker

The Docker compose file is designed for development and testing purposes. But is also a good reference. It provides all components and their dependencies including a Bitcoin Core regtest node and a Neutrino server. Optionally it also spins up Tor for the directory server hidden service and a Jam container for testing interoperability with the reference JoinMarket implementation.

## License

MIT License. See [LICENSE](./LICENSE) for details.
