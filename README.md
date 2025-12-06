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

1. ✅ **Phase 1: Core Library** - Protocol definitions, crypto primitives, and shared models (`jmcore`)
2. ✅ **Phase 2: Directory Server** - Peer discovery and message routing relay
3. 🔄 **Phase 3: Orderbook Watcher** - Monitor and aggregate CoinJoin orders (in planning)
4. 📋 **Phase 4: Client Implementation** - Maker and taker bots (planned)
5. 🔮 **Phase 5: Protocol Extensions** - Alternative directory servers (e.g., Nostr relays), [CoinJoinXT](https://www.youtube.com/watch?v=YS0MksuMl9k) with Lightning Network integration for improved privacy (fees, change, etc.) - details TBD

All components maintain backwards compatibility with the reference implementation during the transition.

## Project Structure

```
jm-refactor/
├── jmcore/              # Shared library for all JoinMarket components
│   ├── src/jmcore/      # Core protocol, crypto, and messaging primitives
│   └── tests/           # Tests for shared library
├── directory_server/    # Directory/relay server implementation
│   ├── src/             # Server implementation
│   ├── tests/           # Server tests
│   └── docker/          # Dockerfile and configs
└── orderbook_watcher/   # Orderbook aggregation and monitoring
    ├── src/             # Watcher implementation
    ├── static/          # Web UI
    └── tests/           # Watcher tests
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

## Nostr Integration (PoC)

We are experimenting with [Nostr](https://nostr.com/) as a resilient, decentralized transport layer for JoinMarket offers. This Proof of Concept (PoC) allows makers to publish offers to Nostr relays and the Orderbook Watcher to aggregate them.

### Running the PoC

1. **Start a local Nostr relay**:
   ```bash
   docker-compose -f docker-compose.nostr.yml up -d
   ```
   This starts a relay at `ws://localhost:7777`.

2. **Publish Dummy Offers**:
   We have provided scripts to publish random offers to the relay.
   ```bash
   python scripts/nostr_publish.py
   ```

3. **Configure Orderbook Watcher**:
   Update your environment variables to listen to the relay.
   ```bash
   export NOSTR_RELAYS=ws://localhost:7777
   ```
   Or add it to your `.env` file.

4. **Run the Watcher**:
   Start the watcher as usual. It will now fetch offers from both the configured directory nodes and the Nostr relays.
   ```bash
   cd orderbook_watcher
   python -m orderbook_watcher.main
   ```

## Development Philosophy

- **SOLID Principles**: Clean architecture with clear separation of concerns
- **Type Safety**: Full Pydantic models and type hints
- **Modern Python**: Python 3.14+ features, async/await where beneficial
- **Performance**: Optimized for low latency and high throughput
- **Observability**: Structured logging with loguru
- **Testability**: High test coverage with pytest
- **Code Quality**: Pre-commit hooks with ruff for linting and formatting

See more at [ARCHITECTURE.md](./ARCHITECTURE.md).

## Getting Started

See individual component READMEs for detailed instructions:

- [jmcore](./jmcore/README.md)
- [Directory Server](./directory_server/README.md)
- [Orderbook Watcher](./orderbook_watcher/README.md)

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

## License

MIT License. See [LICENSE](./LICENSE) for details.
