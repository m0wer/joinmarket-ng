# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Descriptor Wallet Backend now exposed via CLI**: Users can now select `--backend descriptor_wallet` for fast UTXO tracking.
  - Available in all CLIs: `jm-wallet`, `jm-maker`, `jm-taker`
  - Uses Bitcoin Core's `importdescriptors` for one-time wallet setup
  - Fast syncs via `listunspent` (~1s vs ~90s for scantxoutset)
  - Automatic descriptor import and wallet setup on first use
  - **New default backend** for maker, taker, and wallet commands (changed from `full_node`)
  - Docker compose examples updated to use `descriptor_wallet` by default
- **Operator Notifications**: Push notification system via Apprise for CoinJoin events.
  - Supports 100+ notification services (Gotify, Telegram, Discord, Pushover, email, etc.)
  - Privacy-aware: configurable amount/txid/nick inclusion
  - Per-event toggles for fine-grained control
  - Fire-and-forget: notifications never block protocol operations
  - New optional dependency: `pip install jmcore[notifications]`
  - Components integrated: Maker, Taker, Directory Server, Orderbook Watcher
  - Docker images now include `apprise` by default for notification support
- **DescriptorWalletBackend**: New Bitcoin Core backend using descriptor wallets for efficient UTXO tracking.
  - Uses `importdescriptors` RPC for one-time wallet setup
  - Uses `listunspent` RPC for fast UTXO queries (O(wallet) vs O(UTXO set))
  - Persistent tracking: Bitcoin Core maintains UTXO state automatically
  - Real-time mempool awareness: sees unconfirmed transactions immediately
  - Deterministic wallet naming based on mnemonic fingerprint
- `setup_descriptor_wallet()` method in WalletService for one-time descriptor import
- `sync_with_descriptor_wallet()` method for fast wallet sync via listunspent
- Helper functions `generate_wallet_name()` and `get_mnemonic_fingerprint()` for deterministic wallet naming
- Early backend connection validation in taker CLI before wallet sync.
- Estimated transaction fee logging before user confirmation prompt (assumes 1 input per maker + 20% buffer).
- Final transaction summary before broadcast with exact input/output counts, maker fees, and mining fees.
- Support for broadcast confirmation callback to allow user to review transaction before broadcasting.
- `has_mempool_access()` method to BlockchainBackend for detecting mempool visibility.
- `BroadcastPolicy.MULTIPLE_PEERS` - new broadcast policy that sends to N random makers (default 3).
- `broadcast_peer_count` configuration parameter to control number of peers for MULTIPLE_PEERS policy.
- Unified broadcast behavior between full node and Neutrino clients.
- Comprehensive backend comparison documentation in jmwallet README with performance characteristics and use cases.
- **Smart Scan for Descriptor Wallet**: Fast startup for descriptor wallet import on mainnet.
  - Initial import only scans ~1 year of blockchain history (52,560 blocks)
  - Reduces first-time wallet sync from 20+ minutes to seconds on mainnet
  - Background full rescan runs automatically to ensure no old transactions are missed
  - Configurable via `smart_scan`, `background_full_rescan`, `scan_lookback_blocks` in WalletConfig

### Changed

- **Default backend changed from `full_node` to `descriptor_wallet`** for all components (maker, taker, wallet CLI).
  - Full node (scantxoutset) still available via `--backend full_node`
  - Provides significant performance improvement for ongoing operations (~1s vs ~90s per sync)
  - Docker compose examples updated to use descriptor_wallet by default
- Fee rate handling improvements:
  - Changed default fee rate from 10 sat/vB to 1 sat/vB fallback.
  - Added support for sub-1 sat/vB fee rates (float instead of int).
  - Added `--block-target` option for fee estimation (1-1008 blocks).
  - Added `--fee-rate` option for manual fee rate (mutually exclusive with `--block-target`).
  - Default behavior: 3-block fee estimation when connected to full node.
  - Neutrino backend: falls back to 1 sat/vB (cannot estimate fees).
  - Error when `--block-target` is used with neutrino backend.
- Backend `estimate_fee()` now returns `float` for precision with sub-sat rates.
- Added `can_estimate_fee()` method to backends for capability detection.
- Increased default counterparty count from 3 to 10 makers.
- Reduced logging verbosity: parsed offers, fidelity bond creation, and Neutrino operations now logged at DEBUG level.
- Improved sweep coinjoin logging: initial "Starting CoinJoin" message now shows "ALL (sweep)" instead of "0 sats".
- **Default broadcast policy changed from RANDOM_PEER to MULTIPLE_PEERS** (sends to 3 random makers).
- **Unified broadcast behavior**: All policies (SELF, RANDOM_PEER, MULTIPLE_PEERS, NOT_SELF) work
  the same way for both full node and Neutrino backends. The only difference is Neutrino skips
  mempool verification when falling back to self-broadcast.
- RANDOM_PEER and MULTIPLE_PEERS now allow self-fallback if all makers fail (both full node and Neutrino).
- Neutrino pending transaction timeout reduced from 48h to 10h before warning.
- Neutrino pending transaction monitoring uses block-based UTXO verification (cannot access mempool).
- Neutrino backend UTXO detection improved with incremental rescans and retries for better robustness.

### Fixed

- **Taker failing when Maker uses multiple UTXOs**: Fixed handling of multiple `!sig` messages from makers with multiple inputs.
- **Orderbook Watcher showing only few offers despite receiving many from directories**.
  - Directory servers send realtime PEERLIST updates (one per peer) when peers connect/disconnect.
  - DirectoryClient was incorrectly treating these partial updates as complete peerlist replacements.
  - Now accumulates active peers from partial responses instead of replacing the entire list.
  - Only removes offers for nicks explicitly marked as disconnected (`;D` suffix).
  - Periodic peerlist refresh now collects active nicks from ALL directories before cleanup.
  - This fixes orderbooks being pruned down to just the most recently seen makers.
- Critical maker transaction fee calculation bug causing "Change output value too low" errors.
  - Maker `txfee` from offers is the total transaction fee contribution (in satoshis), not per-input/output.
  - Previously incorrectly multiplied `offer.txfee` by `(num_inputs + num_outputs + 1)`, causing maker change calculations to fail.
  - Now correctly uses `offer.txfee` directly as per JoinMarket protocol specification.
- Concurrent read bug in TCPConnection causing "readuntil() called while another coroutine is already waiting" errors.
  - Added receive lock to serialize concurrent `receive()` calls on the same connection.
  - This fixes race conditions when `listen_continuously()` and `get_peerlist_with_features()` run concurrently.
- Wallet address alignment in `jm-wallet info --extended` output.
  - Fixed misalignment when address indices transition from single to double digits (e.g., 9 to 10).
  - Derivation paths now use fixed-width padding (24 characters) for consistent column alignment.

## [0.8.0] - 2026-01-08

### Added

- Support for multiple directory servers with message deduplication.
- Maker health checking via direct onion connection.
- BIP39 passphrase support for wallets (CLI and component integration).
- BIP84 zpub support for native SegWit wallets.
- Auto-discovery for fidelity bonds and timenumber utilities.
- Configuration for separate Tor hidden service targets (split onion serving host).
- Tests for BIP39 passphrase and multi-directory functionality.

### Fixed

- Flaky E2E tests regarding taker commitment clearing and neutrino blacklist resetting.
- Detection of peer count after CoinJoin confirmation in Maker bot.

## [0.7.0] - 2026-01-03

### Added

- Generic per-peer rate limiting across all components.
- Specific rate limiting for orderbook requests to prevent spam.
- Fidelity bond proof compatibility and analysis tool.
- Exponential backoff and banning for orderbook rate limiter.
- Docker multi-architecture builds (ARM support).
- Periodic directory connection status logging.
- `INSTALL.md` with detailed installation instructions.
- Support for `MNEMONIC_FILE` environment variable.
- SimpleX community link to README.

### Changed

- Unified data directory to `~/.joinmarket-ng`.
- Improved Dockerfile efficiency with multi-stage builds.
- Moved to `prek` action for CI.
- Renamed project title to JoinMarket NG in documentation and orderbook watcher.

### Fixed

- Linking of standalone fidelity bonds to offers in Orderbook Watcher.
- Maker orderbook rate limit logging.
- Docker layer caching for ARM builds.

## [0.6.0] - 2025-12-28

### Added

- Persistence for PoDLE commitment blacklist.
- Tracking of CoinJoin transaction confirmations in wallet history.
- Stale offer filtering.
- UTXO max PoDLE retries for makers.
- Advanced UTXO selection strategies for takers and makers.
- Configurable dust threshold for CoinJoin transactions.
- Periodic wallet rescan.
- CoinJoin notifier script.

### Changed

- Redesigned dependency management.
- Moved `CommitmentBlacklist` to `jmcore`.
- Moved to integer satoshi amounts for Bitcoin values to avoid float issues.

### Fixed

- Maker change calculation bug causing negative change.
- Directory server message routing concurrency.
- Fee estimation and Bitcoin units display format.
- Maker sending fidelity bonds via PRIVMSG.

## [0.5.0] - 2025-12-21

### Added

- Protocol v5 extension feature for Neutrino support.
- Feature negotiation via handshake (`neutrino_compat`).
- Push broadcast policy for taker.
- Auto-miner for regtest in Docker Compose.
- Mnemonic generation, encryption, and fidelity bond generation.
- JSON-line message parsing limits to prevent DoS.
- Support for Tor ephemeral hidden services and Cookie Auth.

### Changed

- Migrated from `cryptography` to `coincurve` for ECDSA operations.
- Adopted feature flags instead of strict protocol version bumps.
- Consolidated documentation into `DOCS.md`.

### Fixed

- Taker fee limit checks.
- Fidelity bond proof verification and generation.
- Reference implementation compatibility.

## [0.4.0] - 2025-12-14

### Added

- Complete Maker Bot implementation with fidelity bonds and signing.
- Taker implementation with input signing.
- Neutrino backend integration.
- `AGENTS.md` for AI agents documentation.
- Comprehensive E2E tests with Docker Compose.

### Changed

- CI workflow to always run all tests.
- Updated READMEs for components.

### Fixed

- Blockchain height consistency in E2E tests.
- GitHub Actions workflow to start Bitcoin Regtest node properly.

## [0.3.0] - 2025-12-07

### Added

- Health check and monitoring features to Directory Server.
- Fidelity bond offer counts to directory stats.
- Docker health check for directory server.
- Debug Docker image with `pdbpp` and `memray`.

### Changed

- Increased max message size to 2MB.
- Increased max peers limit to 10000.
- Set log level to INFO in docker-compose files.

### Fixed

- Orderbook Watcher clean shutdown on SIGTERM/SIGINT.
- Directory Server file-based logging removal.
- Handling of failed peer mappings on send failures.

## [0.2.0] - 2025-11-20

### Added

- Orderbook Watcher component.
- Healthcheck to Orderbook Watcher service.
- Directory node connection status tracking.
- Auto-remove stale offers from inactive counterparties.
- Tor hidden service support for mempool.space integration.

### Fixed

- "Unexpected response type: 687" error.
- Fidelity bond handling for new offers.
- Orderbook request logic improvements.
- Connection handling and UI status indicators.

## [0.1.0] - 2025-11-16

### Added

- Initial project structure.
- Directory Server implementation with Peer Types and Monitoring.
- Basic README and Docker setup.
- Pre-built image support for directory server compose.
- Tor configuration instructions.

[Unreleased]: https://github.com/m0wer/joinmarket-ng/compare/0.8.0...HEAD
[0.8.0]: https://github.com/m0wer/joinmarket-ng/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/m0wer/joinmarket-ng/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/m0wer/joinmarket-ng/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/m0wer/joinmarket-ng/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/m0wer/joinmarket-ng/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/m0wer/joinmarket-ng/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/m0wer/joinmarket-ng/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/m0wer/joinmarket-ng/releases/tag/0.1.0
