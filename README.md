<p align="center">
  <img src="media/logo.svg" alt="JoinMarket NG Logo" width="200"/>
</p>

# JoinMarket NG

> **⚠️ IMPORTANT NOTICE**
> This project is production-ready but very new to mainnet usage. While all components are fully implemented and tested, mainnet deployment experience is limited. **USE AT YOUR OWN RISK - NO WARRANTIES PROVIDED.**
> The project is in very active development and the API/configuration may change significantly until the first official release.

Modern, clean alternative implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/) components.

- Live orderbook: https://joinmarket-ng.sgn.space/
- Live docs:https://m0wer.github.io/joinmarket-ng/

## What is JoinMarket?

**JoinMarket is a decentralized CoinJoin protocol for Bitcoin privacy.**

CoinJoin transactions combine multiple users' funds into a single transaction, making it difficult to trace the the coins. This enhances financial privacy.

How it works is by crafting a transaction with several equal amount outputs from inputs belonging to different users. This way, an outside observer cannot determine which input corresponds to which equal amount output, effectively obfuscating the transaction history.
Change outputs are also included, but they are of different amounts and can be easily identified as change and sometimes matched to inputs using heuristics. However, the equal amount outputs remain ambiguous.

One round of CoinJoin increases privacy, but generally multiple rounds are needed to achieve strong anonymity. JoinMarket facilitates this by connecting users who want to mix their coins (takers) with those willing to provide liquidity for a fee (makers).

### Why Financial Privacy Matters

Just as you wouldn't want your employer to see your bank balance when paying you, or a friend to know your net worth when splitting a bill, Bitcoin users deserve financial privacy. JoinMarket helps individuals exercise their right to financial freedom without promoting illegal activities.

### What Makes JoinMarket Different

Unlike other CoinJoin implementations (Wasabi, Whirlpool), JoinMarket has **no central coordinator**:

- **Taker acts as coordinator**: Chooses peers, gains maximum privacy (doesn't share inputs/outputs with a centralized party)
- **Most censorship-resistant**: Directory servers are easily replaceable and don't route communications, only host the orderbook
- **Multiple fallbacks**: Works with IRC, Tor hidden services, and can easily move to alternatives like Nostr relays
- **Peer-to-peer**: Direct encrypted communication between participants

### JoinMarket-NG vs Reference Implementation

This is a modern alternative implementation of the JoinMarket protocol, maintaining **full wire protocol compatibility** with the [reference implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/) while offering significant improvements.

#### Key Advantages

**Architectural Improvements:**
- **Stateless, no daemon**: Simpler deployment and operation
- **Run multiple roles simultaneously**: Act as maker and taker at the same time without stopping/restarting - huge privacy win by avoiding suspicious orderbook gaps
- **Light client support**: Full Neutrino/BIP157 integration - no full node required
- **No wallet daemon**: Direct wallet access without RPC overhead or remote wallet complexity
- **Modern async stack**: Python 3.14+, Pydantic v2, AsyncIO with full type hints

**Quality & Maintainability:**
- **~100% unit test coverage**: Every component thoroughly tested in isolation
- **E2E compatibility tests**: Full CoinJoin flows tested against reference implementation
- **Type safety**: Strict type hints enforced with Mypy (static type checker) and Pydantic (runtime data validation)
- **Clean, auditable code**: Easy to understand, review, and contribute to
- **Modern tooling**: Ruff formatting, pre-commit hooks, comprehensive CI/CD

#### Why a New Implementation?

The reference implementation has served the community well, but faces challenges that make improvements difficult:
- Limited active development (maintenance mode)
- 181+ open issues and 41+ open pull requests
- Technical debt requiring full rewrites
- Tight coupling to Bitcoin Core's BerkeleyDB

Starting fresh let us build on modern foundations while honoring the protocol's proven design. This project currently lacks peer review (contributions welcome!), but the extensive test suite and clear documentation make auditing straightforward.

**We see this as our turn to take JoinMarket to the next level while honoring the foundation built by the original contributors.**

### Tor Integration

All JoinMarket components use Tor for privacy, but in different ways:

| Component | Tor SOCKS Proxy | Tor Hidden Service | Notes |
|-----------|----------------|-------------------|-------|
| **Directory Server** | ❌ No | ✅ Permanent | Receives-only; stable `.onion` address for users |
| **Maker Bot** | ✅ Yes | ✅ Ephemeral | Connects to dirs + serves incoming connections |
| **Taker Bot** | ✅ Yes | ❌ No | Connects to dirs + makers only |
| **Orderbook Watcher** | ✅ Yes | ❌ No | Monitors dirs only; advertises `NOT-SERVING-ONION` |

**Why different approaches?**
- **Directory servers** need permanent addresses so users can save them in configs
- **Makers** use ephemeral (temporary) hidden services for better privacy - fresh identity each session
- **Takers/watchers** only make outgoing connections, so they don't need hidden services at all

See [DOCS.md § Tor Integration](./DOCS.md#tor-integration) for configuration details.

### Roadmap

All components are fully implemented. Future work will focus on improvements, optimizations, and protocol extensions:

- Nostr relays for offer broadcasting
- CoinJoinXT and Lightning Network integration: https://www.youtube.com/watch?v=YS0MksuMl9k

### Compatibility & Feature Negotiation

This implementation uses protocol v5 and maintains **full wire protocol compatibility** with the reference implementation. New features like Neutrino support are negotiated via the handshake features dict, not protocol version bumps.

**Design principles:**
- **Smooth rollout**: Features are adopted gradually without requiring network-wide upgrades
- **No fragmentation**: All peers use protocol v5, avoiding version-based compatibility issues
- **Backwards compatible**: New peers work seamlessly with existing JoinMarket makers and takers

**Feature negotiation via handshake:**
- During the CoinJoin handshake, peers exchange a features dict (e.g., `{"neutrino_compat": true}`)
- Takers adapt their UTXO format based on maker capabilities
- Legacy peers that don't advertise features receive legacy format

**Compatibility matrix:**
| Taker Backend | Maker Features | Status |
|--------------|----------------|--------|
| Full node | No `neutrino_compat` (legacy) | ✅ Works - sends legacy UTXO format |
| Full node | Has `neutrino_compat` | ✅ Works - sends extended UTXO format |
| Neutrino | No `neutrino_compat` (legacy) | ❌ Incompatible - taker filters out |
| Neutrino | Has `neutrino_compat` | ✅ Works - both use extended format |

Neutrino takers automatically filter out makers that don't advertise `neutrino_compat` since they require extended UTXO metadata for verification.

## Project Structure

```
joinmarket-ng/
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

- **No full node required**: ~100MB storage vs ~1TB for Bitcoin Core
- **Privacy-preserving**: Downloads filters, not addresses (unlike Bloom filters)
- **Fast sync**: Minutes instead of days
- **Written in Go**: Wraps lightninglabs/neutrino library
- **REST API**: Simple HTTP interface for wallet integration

## Getting Started

### Installation

For local development, install dependencies in order:

```bash
# 1. Install jmcore (foundation)
cd jmcore
pip install -r requirements.txt
pip install -e .

# 2. Install jmwallet
cd ../jmwallet
pip install -r requirements.txt
pip install -e .

# 3. Install maker/taker/etc.
cd ../maker
pip install -r requirements.txt
pip install -e .
```

For development with testing tools:

```bash
# After production install
pip install -r requirements-dev.txt
```

See [DOCS.md § Dependency Management](./DOCS.md#dependency-management) for complete dependency management documentation.

### Component Documentation

See individual component READMEs for detailed instructions:

- [jmcore](./jmcore/README.md) - Core library
- [jmwallet](./jmwallet/) - Wallet library
- [Directory Server](./directory_server/README.md) - Message relay
- [Orderbook Watcher](./orderbook_watcher/README.md) - Market monitoring
- [Maker Bot](./maker/README.md) - Yield generator
- [Taker Bot](./taker/README.md) - CoinJoin participant
- [E2E Tests](./tests/e2e/README.md) - Complete system tests
- [Protocol & Architecture Documentation](./DOCS.md) - Full technical documentation

## Utility Scripts

The `scripts/` directory contains helpful utilities:

- **build_docs.py** - Generates API documentation from source code
- **coinjoin_notifier.py** - Daemon that monitors CoinJoin history and sends Gotify notifications for new transactions
- **fund-test-wallets.sh** - Funds test wallets in regtest environment
- **generate_tor_keys.py** - Generates Tor hidden service keys
- **regtest-miner.sh** - Automated block mining for regtest
- **run_all_tests.sh** - Runs complete test suite with Docker orchestration
- **update-deps.sh** - Updates Python dependencies across all components

## Docker

The Docker compose file is designed for development and testing purposes. But is also a good reference. It provides all components and their dependencies including a Bitcoin Core regtest node and a Neutrino server. Optionally it also spins up Tor for the directory server hidden service and a JAM (JoinMarket web UI) container for testing interoperability with the reference JoinMarket implementation.

## License

MIT License. See [LICENSE](./LICENSE) for details.

## Community

Join the JoinMarket community to discuss, get help, and stay updated:

- **Telegram**: https://t.me/joinmarketorg
