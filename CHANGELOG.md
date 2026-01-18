# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Improved Wallet Info Display**: Redesigned the `jm-wallet info` output to be clearer and less misleading:
  - **Standard view**: Balance and deposit addresses are now shown on separate lines with clear headers, instead of on the same line which could be misinterpreted as showing the balance at that specific address.
  - **Extended view**: Added a legend explaining address status labels (new, deposit, cj-out, non-cj-change, used-empty, flagged) so users can understand why addresses were skipped or marked as do-not-reuse.

- **Unconfirmed Transaction Display in Wallet Info**: The `jm-wallet info --extended` command now shows "(unconfirmed)" status for addresses with unconfirmed UTXOs. This detects pending transactions directly from the Bitcoin backend (via `listunspent` with `minconf=0`), providing visibility into unconfirmed funds even for direct sends that aren't tracked in CoinJoin history.

- **Spent Address Shows "used-empty" Instead of "new"**: Fixed a bug in `jm-wallet info --extended` where an address that previously had funds but was spent (outside of CoinJoin) would incorrectly show as "new" with 0 balance instead of "used-empty". The address display range calculation now correctly considers general blockchain activity (`addresses_with_history`) in addition to CoinJoin history.

- **Pending Transaction Timeout**: Maker now automatically marks pending CoinJoin transactions as failed after 60 minutes (configurable via `pending_tx_timeout_min` setting). This prevents the transaction history from being cluttered with entries that the taker never broadcast. Previously, these entries would remain in "pending" state indefinitely, causing repeated (and noisy) transaction lookup attempts in the logs.

- **Mempool Min Fee Check for Wallet Send**: The `jm-wallet send` command now checks the fee rate against the node's mempool minimum fee (like the taker already does). If a manual `--fee-rate` is below the node's `minrelaytxfee`, a warning is logged and the mempool minimum is used instead, preventing "min relay fee not met" broadcast failures.

- **Minimum Relay Fee Documentation**: Added new section to DOCS.md explaining Bitcoin node fee rate configuration, including how to enable sub-satoshi fee rates via `minrelaytxfee` in `bitcoin.conf`.

- **Log Level CLI Flag Across All Components**: Added `--log-level` / `-l` flag to all CLI commands that were missing it:
  - `jm-maker start` and `jm-maker generate-address` commands
  - `jm-directory-server` CLI (status, health subcommands)
  - `jm-orderbook-watcher` main entry point
  - The flag accepts TRACE, DEBUG, INFO, WARNING, and ERROR levels (TRACE was not documented before)
  - Updated `config.toml.template` and settings documentation to include TRACE as a valid log level
  - Environment variable for log level is `LOGGING__LEVEL` (not `LOGGING__LOG_LEVEL` - the latter never worked)

- **Wallet Name in Startup Logs**: Both maker and taker now log the Bitcoin Core descriptor wallet name (e.g., `jm_xxxxxxxx_mainnet`) during startup when using the descriptor wallet backend. This makes it easier to identify which wallet is being used, especially when running multiple instances.

- **Accurate Fee Rate in Final Transaction Summary**: The taker's final transaction summary now displays the actual mining fee and fee rate calculated from the signed transaction. Previously, only the estimated fee was shown, which didn't account for residual/dust amounts absorbed into the fee when change would be below dust threshold. This is especially important for sweep transactions where the actual fee can be significantly higher than the estimate. The summary now shows actual vsize alongside byte size.

- **Automatic Password Prompt for Encrypted Mnemonics**: All CLI commands that load mnemonic files now automatically detect encrypted files (Fernet (AES)) and prompt for a password interactively. Previously, users had to explicitly pass `--password` on the command line, which led to confusing errors when trying to use encrypted mnemonic files. This works across `jm-taker`, `jm-maker`, and `jm-wallet` commands.

- **Password Confirmation Retry Loop**: The `jm-wallet import` and `jm-wallet generate` commands now retry password confirmation up to 3 times when passwords don't match, instead of immediately exiting. This improves the user experience by allowing correction of typos without having to restart the command.

- **BIP39 Passphrase Prompt for Maker/Taker**: Added `--prompt-bip39-passphrase` option to `jm-maker start` and `jm-taker coinjoin` commands. This allows users to enter their BIP39 passphrase interactively at startup rather than passing it via environment variable or command line argument.

- **Wallet Scan Start Height Setting**: New `scan_start_height` configuration option in `[wallet]` section allows specifying an explicit block height for initial wallet scanning. This is useful when you know when your wallet was first used, enabling faster initial sync for newer wallets.

- **Fee Rate Configuration Option**: Added `fee_rate` option to `[taker]` config section for manual fee rate specification in sat/vB. This takes precedence over `fee_block_target` when set, useful for users who prefer explicit fee rates over estimation.

- **Troubleshooting Documentation**: Added new "Troubleshooting" section to DOCS.md with:
  - Common `bitcoin-cli` debugging commands for wallet sync issues
  - Smart scan configuration tips for faster initial sync
  - RPC timeout troubleshooting guide

- **Reproducible Docker Builds**: All Docker images now support reproducible builds using `SOURCE_DATE_EPOCH`. This allows anyone to verify that released images were built from the published source code.
  - Dockerfiles updated to use `SOURCE_DATE_EPOCH` build arg for consistent timestamps
  - CI/CD workflows pass git commit timestamp to builds
  - Release workflow generates manifest files with image digests
  - New verification script: `scripts/verify-release.sh` to verify GPG signatures and image digests
  - New signing script: `scripts/sign-release.sh` for trusted parties to attest releases
  - GPG signature infrastructure in `signatures/` directory
  - Documentation added to DOCS.md and README.md

- **Directory Server Auto-Reconnection**: Makers now automatically attempt to reconnect to disconnected directory servers. This improves maker uptime and resilience against temporary network issues or directory server restarts. Previously, if a maker lost connection to a directory server during startup or due to network issues, it would remain disconnected indefinitely.
  - New config options: `directory_reconnect_interval` (default: 300s/5min) and `directory_reconnect_max_retries` (default: 0 = unlimited)
  - On successful reconnection, offers are automatically re-announced to the reconnected directory
  - Notifications are sent for both disconnections and successful reconnections

- **External Wallet Fidelity Bonds (Cold Storage Support)**: Added support for fidelity bonds with external wallet (hardware wallet/cold storage) private keys. The bond UTXO private key never needs to touch an internet-connected device. Instead, users create a certificate chain where the cold wallet signs a certificate authorizing a hot wallet keypair to sign nick proofs on its behalf.
  - New CLI commands:
    - `jm-wallet create-bond-address <pubkey>`: Create bond address from public key (no mnemonic needed)
    - `jm-wallet generate-hot-keypair`: Generate hot wallet keypair for certificate
    - `jm-wallet prepare-certificate-message`: Create message for hardware wallet signing
    - `jm-wallet import-certificate`: Import signed certificate into bond registry
  - Certificate chain: `UTXO keypair (cold) -> signs -> certificate (hot) -> signs -> nick proofs`
  - Security benefits: Bond funds remain completely safe in cold storage; certificate has configurable expiry (~2 years default); if hot wallet is compromised, only certificate is at risk
  - Compatible with hardware wallets via Sparrow Wallet message signing

- **Multi-Offer Support (Dual Offers)**: Makers can now advertise both relative and absolute fee offers simultaneously with different offer IDs. This allows makers to serve different types of takers (those preferring percentage-based fees vs fixed fees) from a single instance.
  - New `--dual-offers` CLI flag for `jm-maker start` creates both offer types automatically
  - Each offer type gets a unique offer ID (0 for relative, 1 for absolute)
  - !fill requests are routed to the correct offer based on the offer ID
  - Fidelity bond value is shared across all offers
  - Extensible architecture: `offer_configs` list in `MakerConfig` allows N offers (internal API, not yet exposed via CLI for simplicity)
  - Usage: `jm-maker start --dual-offers --cj-fee-relative 0.001 --cj-fee-absolute 500`

- **Wallet Import Command**: New `jm-wallet import` command to recover existing wallets from BIP39 mnemonic phrases. Features interactive word-by-word input with Tab completion (where readline is available), automatic word auto-completion when only one BIP39 word matches the prefix, suggestions display when multiple words match, mnemonic checksum validation after entry, and optional encryption of the saved wallet file. Supports 12, 15, 18, 21, and 24-word mnemonics.

### Fixed

- **Log Level from Config/Env Ignored**: Fixed a bug where `LOGGING__LEVEL` environment variable and `[logging] level` config setting were ignored by CLI commands. The `--log-level` CLI argument worked correctly, but the env/config values were never applied because logging was configured before settings were loaded. Now the priority is: CLI argument > env/config > default ("INFO").

- **Maker cj_fee_absolute config setting ignored**: Fixed bug where setting `cj_fee_absolute` in `config.toml` had no effect because the maker always defaulted to relative fee offers. Added new `offer_type` setting to the `[maker]` config section that allows specifying which fee type to use: `sw0reloffer` (relative, default) or `sw0absoffer` (absolute). Previously, the only way to use absolute fees was via the `--cj-fee-absolute` CLI flag.

- **Install script missing python3-dev dependency**: Added `python3-dev` to the install script's dependency checks. This package is required for building Python C extensions (like the cryptography library used for wallet encryption). Previously, installations would fail when trying to install jmcore if this package was missing, and the script would exit before creating the activation script.

- **Tor cookie path auto-detection order**: Reordered the auto-detection paths for Tor cookie authentication to prioritize `/run/tor/control.authcookie` (common on Debian/Ubuntu with systemd) over `/var/lib/tor/control_auth_cookie`. Previously, the less common path was checked first, causing auto-detection to fail on most modern Linux systems.

- **Taker --fee-rate validation error with default fee_block_target**: Fixed bug where specifying `--fee-rate` on the CLI would fail with "Cannot specify both fee_rate and fee_block_target" error even when fee_block_target was not explicitly set. The issue was that `build_taker_config()` unconditionally fell back to `wallet.default_fee_block_target` (default: 3) even when `fee_rate` was provided. Now `fee_block_target` is only set when `fee_rate` is not provided.

- **Channel consistency check allows messages from different directory servers**: Fixed false positive channel consistency violations when taker messages arrived via different directory servers. The JoinMarket protocol broadcasts messages to ALL directory servers, so receiving `!auth` from `dir:serverA` after `!fill` from `dir:serverB` is expected behavior. The check now only validates that "direct" and "directory" channel types are not mixed, not the specific server identity.

- **Direct message parse failures now logged with content**: When the maker fails to parse a direct message, the log now includes a preview of the message content (truncated to 100 chars) to aid debugging. Previously only logged "Failed to parse direct message" with no indication of what was received.

- **Rate limiting for direct message parse failure warnings**: Parse failure warnings are now rate-limited (1 per 10 seconds per peer) to prevent log spam when receiving repeated malformed messages from the same peer.

- **Chunked PEERLIST responses**: Directory server now sends PEERLIST responses in chunks of 20 peers instead of a single massive message. This fixes timeout issues when receiving large peerlists over slow Tor connections. Previously, mainnet directories with hundreds of peers would frequently timeout because the entire peerlist had to be transmitted in one message. The client now accumulates peers from multiple PEERLIST messages, using a 5-second inter-chunk timeout to detect when all chunks have been received.

- **CoinJoin output destination address path**: Changed INTERNAL destination addresses to use internal chain (/1) instead of external chain (/0). This matches the reference implementation where all JoinMarket-generated addresses (CJ outputs and change) use the internal branch, while external (/0) is reserved for user-facing deposit addresses.

- **Fee rate randomization (tx_fee_factor)**: Changed from a simple multiplier (default 3.0x) to randomization like the reference implementation. Fees are now randomized between `base_fee` and `base_fee * (1 + tx_fee_factor)` for privacy. Default changed from 3.0 to 0.2 (20% randomization range). Set to 0 to disable randomization.

- **Fee rate resolution with mempool minimum**: Fee estimation now checks against mempool minimum fee and uses the higher value. Manual fee rates below mempool minimum trigger a warning and use mempool minimum instead. This prevents transactions from being rejected due to insufficient fee.

- **Interactive UTXO selection (--select-utxos) logging**: Improved logging for `--select-utxos` in sweep mode to better indicate whether UTXOs were manually selected or all UTXOs were used. This helps debug cases where the interactive selector might not appear.

### Improved

- **BIP39 Passphrase Documentation**: Expanded DOCS.md to clarify that `jm-wallet import` only stores the mnemonic without the BIP39 passphrase. The passphrase is provided when using the wallet (via `--bip39-passphrase`, `--prompt-bip39-passphrase`, or `BIP39_PASSPHRASE` env var).

- **Config Template Clarity**: Improved `config.toml.template` comments to:
  - Distinguish "coinjoin fees" (paid to makers) from "network/miner fees"
  - Document `fee_rate` option precedence over `fee_block_target`
  - Explain smart scan and background rescan behavior for wallet import

- **Orderbook watcher feature detection**: Fixed race condition where offers from new makers were stored with empty features before the peerlist response arrived. Now when peerlist response arrives with features, all cached offers for those makers are retroactively updated with the correct features.

- **Peer location updates now include features**: Fixed directory server to include peer features (neutrino_compat, peerlist_features) in peer location update messages sent after private message routing. Previously, when a client learned about a new peer through a PEERLIST update (not via explicit GETPEERLIST request), the features were missing. This caused orderbook watchers to miss feature information for makers discovered through private message routing.

- **Faster feature discovery for new makers**: Improved orderbook watcher feature discovery timing:
  - Added immediate feature discovery (30 seconds after startup) instead of waiting 10 minutes for first health check
  - Reduced initial health check delay from 10 minutes to 2 minutes
  - Added automatic feature discovery for makers without features after each peerlist refresh (every 5 minutes)
  - Direct health checks now populate features in directory client caches, ensuring offers are tagged with correct features

- **Feature merging across directories**: Fixed issue where maker features (neutrino_compat, peerlist_features) were being overwritten instead of merged when receiving updates from multiple directory sources. When a PEERLIST came from a reference directory (no features), it would overwrite features previously learned from an NG directory. Now features are properly merged: once we learn a feature for a nick, we keep it. This ensures the orderbook watcher and taker correctly detect maker capabilities regardless of which directory responds first.

- **Multiple offers per maker with same bond**: Fixed bond deduplication in orderbook watcher incorrectly dropping offers when a maker advertises multiple offer IDs (e.g., oid=0 and oid=1) backed by the same fidelity bond. Previously, only one offer was kept per bond UTXO. Now the deduplication key includes both the bond UTXO and offer ID, preserving all distinct offers from the same maker while still deduplicating when different nicks share the same bond (maker restart scenario).

- **Maker direct connection handshake support**: Makers now respond to handshake requests on direct connections (via their hidden service). This enables health checkers and feature discovery tools to connect directly to makers and discover their features (neutrino_compat, peerlist_features) without relying on directory server peerlists. Previously, direct connections only handled CoinJoin protocol messages (fill, auth, tx, push), causing health checks to time out and feature discovery to fail for NG makers.

- **Direct connection orderbook requests**: Makers now properly handle `!orderbook` requests received via direct connection (PUBMSG type 687). Previously, orderbook requests sent over direct connections were ignored with "Failed to parse direct message" warnings, because the maker only handled PRIVMSG (type 685) on direct connections. This was causing repeated warnings like `'{"type": 687, "line": "J5xxx!PUBLIC!orderbook"}'`. Now these requests are processed with the same rate limiting as directory-relayed requests.

- **Improved rate limiting and ban logging**: Added DEBUG/TRACE level logging throughout the rate limiter to help diagnose peer behavior:
  - TRACE: Logs each allowed request
  - DEBUG: Logs each rate-limited request with violation count, backoff level, and wait time
  - DEBUG: Logs when banned peer requests are rejected (with remaining ban time)
  - DEBUG: Logs when ban expires and peer state is reset
  - WARNING: Ban events now include the final backoff level for context

- **Improved PoDLE verification logging**: Added DEBUG/TRACE level logging for PoDLE proof verification to help diagnose authentication issues:
  - TRACE: Logs verification inputs (P, P2, sig, e, commitment - truncated)
  - DEBUG: Logs full PoDLE details on success (taker, utxo, commitment)
  - DEBUG: Logs detailed failure reasons including commitment/utxo info
  - DEBUG: Logs UTXO validation details (value, confirmations)
  - DEBUG: Logs specific rejection reasons (too young, too small)

- **Peer feature logging in handshake**: Makers now log advertised peer features (version, network, features) at DEBUG level when receiving handshake requests on direct connections. This helps diagnose feature negotiation and compatibility issues. Supports both reference implementation format (dict: `{"peerlist_features": true}`) and NG format (comma-string: `"neutrino_compat,peerlist_features"`).

- **Improved direct message parse failure logging**: Parse failures now log the full message content at DEBUG level (in addition to the rate-limited WARNING with truncated preview). This helps diagnose protocol issues without flooding logs.

## [0.10.0] - 2026-01-15

### Security

- **Sensitive data protection**: Refactored configuration models to use Pydantic's `SecretStr` type for sensitive fields (mnemonics, passphrases, passwords, destination addresses, notification URLs). This prevents accidental exposure of sensitive data in logs, error messages, and tracebacks. All sensitive values are automatically masked as `**********` in string representations and logging output, while remaining accessible via `.get_secret_value()` when needed.

### Fixed

- **Config file section headers**: Fixed config.toml.template to have all section headers (like `[bitcoin]`, `[tor]`, `[maker]`, etc.) uncommented by default. Previously, users would uncomment individual settings but forget to uncomment the section header, causing the settings to be silently ignored by the TOML parser. This led to confusion where config file settings appeared to be ignored even though they were correctly uncommented.
- **Config file error handling**: Improved error handling for malformed config.toml files. The application now exits immediately with exit code 1 and displays a clear error message when the config file has invalid TOML syntax (e.g., missing closing brackets, invalid characters). Previously, parsing errors were silently logged as warnings, and the application would continue with default values, making it difficult to diagnose configuration issues.
- **jm-directory-ctl config compliance**: Fixed `jm-directory-ctl status` and `jm-directory-ctl health` commands to respect `directory_server.health_check_host` and `directory_server.health_check_port` settings from config.toml. Previously, these commands always used hardcoded defaults (127.0.0.1:8080) and ignored the config file.
- **jm-wallet generate-bond-address config compliance**: Fixed `jm-wallet generate-bond-address` to respect `network_config.network` and `data_dir` settings from config.toml when CLI arguments are not provided. Previously, it always defaulted to mainnet and used hardcoded data directory logic.
- **jm-taker clear-ignored-makers config compliance**: Fixed `jm-taker clear-ignored-makers` to respect `data_dir` setting from config.toml when the `--data-dir` argument is not provided.
- **Orderbook watcher feature detection**: Fixed orderbook watcher to correctly identify JoinMarket NG makers' features (neutrino_compat, peerlist_features). Two issues resolved: (1) When new makers join after orderbook watcher startup, their features weren't being discovered until the next periodic peerlist refresh (5 minutes) or health check (15 minutes). Now the orderbook watcher immediately requests peerlist when discovering new peers to fetch their features. (2) Health checker now properly advertises peerlist_features support in its handshake to extract maker features, and merges these features with offers even when peerlist has already provided some features (health check provides authoritative confirmation via direct connection).
- **Taker pending transaction update on exit**: Fixed issue where taker CoinJoin transactions remained marked as `[PENDING]` in history after successful broadcast. The taker now immediately checks transaction status (mempool for full nodes, block confirmation for Neutrino) right after recording the history entry, before the CLI exits. Additionally, `jm-wallet info` now automatically updates the status of any pending transactions found in history, acting as a safeguard for transactions that confirm after the taker process has exited.
- **Spent address tracking in descriptor wallet**: Fixed issue where addresses that had been used but fully spent (zero balance) were not being tracked in `addresses_with_history`. The descriptor wallet backend now uses `listtransactions` RPC to fetch all addresses with any transaction history, ensuring the wallet correctly tracks which addresses have been used even if they no longer have UTXOs. This prevents address reuse and ensures `jm-wallet info` shows the correct next address.
- **Signature Ordering Mismatch**: Fixed critical bug where maker signatures were matched to the wrong transaction inputs, causing `OP_EQUALVERIFY` failures during broadcast. Root cause: signatures from the reference maker are sent in **transaction input order** (sorted by position in the serialized tx), not in the order UTXOs were originally provided in the `!ioauth` response. The taker now correctly matches signatures to transaction inputs by finding maker UTXOs in the actual transaction input order, rather than assuming they match the `!ioauth` order.
- **Slow Signature Processing**: Fixed 60-second delay between receiving signatures and processing them. Two issues: (1) For `!sig` responses (which expect multiple messages per maker), the loop condition `accumulate_responses and responses` kept waiting for the full timeout even after all signatures were received. Now uses `expected_counts` parameter to know when all signatures are collected. (2) Directory clients were polled sequentially, each waiting up to 5 seconds. Now polls all directories concurrently with `asyncio.gather()` using shorter 1-second chunks to allow more frequent checking of the direct message queue.
- **Sweep Mode CJ Amount Preservation**: Fixed critical bug where reference makers would reject sweep transactions with "wrong change". Root causes: (1) In sweep mode, the taker was recalculating `cj_amount` in `_phase_build_tx` when actual maker inputs differed from the initial estimate. Since makers calculate their expected change based on the original `cj_amount` from the `!fill` message, this recalculation caused a mismatch. (2) The initial tx_fee estimate used only 2 inputs per maker, which was insufficient when makers provided 6+ UTXOs, causing negative residual. The fix: (a) Preserve the original `cj_amount` sent in `!fill` - any tx_fee difference becomes additional miner fee (residual), (b) Use conservative tx_fee estimate (2 inputs/maker + 5 buffer) to minimize negative residual cases, (c) Fail gracefully with clear error when a maker provides many UTXOs causing negative residual (rare edge case).
- **Smart Message Routing**: Fixed `CryptError` with reference makers caused by duplicate `!fill` messages resetting session keys. Taker now intelligently routes messages via a single directory instead of broadcasting to all connected directories.
- **Session Channel Consistency**: Fixed critical protocol error where taker would mix communication channels (directory relay for `!fill`, direct connection for `!auth`) within a single CoinJoin session. This caused reference makers to reject messages as they appeared to be from different sessions. Taker now establishes ONE communication channel per maker before sending `!fill` and uses ONLY that channel for all subsequent messages (`!auth`, `!tx`, `!push`) in that session. Channel selection: tries direct connection first (5s timeout), falls back to directory relay if unavailable.
- **Directory Signature Verification**: Fixed `hostid` used for signing directory-relayed messages. Now correctly uses the fixed `"onion-network"` hostid (matching the reference implementation in `jmdaemon/onionmc.py`) instead of the directory's hostname. Previously, messages relayed through directories were signed with the wrong hostid, causing "nick signature verification failed" errors on reference makers.
- **Direct Peer Connection Message Signing**: Fixed message signing for direct peer-to-peer Tor connections. Messages sent via direct onion connections now include the required signature (pubkey + sig) that reference makers expect. Previously, direct connection messages were sent without signatures, causing reference makers to reject them with "Sig not properly appended to privmsg". The fix adds `nick_identity` parameter to `OnionPeer` and uses `ONION_HOSTID` ("onion-network") as the hostid for signing, matching the reference implementation's expectations.
- **Notification Configuration**: Fixed notification system to respect config file settings. Previously, notifications only read from environment variables (`NOTIFY_URLS`, etc.), completely ignoring the `[notifications]` section in `config.toml`. Now the notification system uses the unified settings system (config file + env vars + CLI args), with proper precedence: CLI args > environment variables > config file > defaults. All components (taker, maker, orderbook watcher, directory server) have been updated to pass settings to `get_notifier()`.
- **Fidelity Bond Verification**: Fixed a bug where fidelity bonds were parsed but not verified against the blockchain, causing their value to be 0. This prevented bond-weighted maker selection from working correctly, falling back to random selection. Taker now verifies bond UTXOs and calculates their value before maker selection.
- **Maker Selection Strategy**: Fixed maker selection to use deterministic mixed bonded/bondless strategy. The bondless allowance determines the proportion of maker slots using fair rounding: with 3 makers and 12.5% allowance, round(3 × 0.875) = 3 bonded slots. Bonded slots are filled by bond-weighted selection (prioritizing high-bond makers), while bondless slots are filled randomly from ALL remaining offers (both bonded and bondless makers, with equal probability). "Bondless" means bond-agnostic, not anti-bond. This ensures bonded makers are consistently rewarded while still supporting new/bondless makers. If insufficient bonded makers exist, remaining slots are filled from all available offers (optionally requiring zero-fee via `bondless_require_zero_fee` flag).
- **Orderbook Timeout**: Increased orderbook request timeout from 10s to 120s based on empirical testing. The previous timeout was missing ~75-80% of available offers. New timeout captures ~95% of offers (95th percentile response time is ~101s over Tor).
- **Peer-to-Peer Handshake Format**: Fixed message format for direct peer connections to use `{"type": 793, "line": "<json>"}` format, matching reference implementation (was using `{"type": 793, "data": {...}}`).
- **Maker Replacement Selection**: Fixed maker replacement to exclude makers already in the current session. Previously, a maker that already responded could be incorrectly re-selected as a replacement, causing commitment rejection errors.
- **Taker peerlist handling**: Fixed taker peerlist handling that was previously ignored. This way we start colelcting peer features and onion addresses earlier.
- **Minimum makers default**: Changed `minimum_makers` default from 2 to 1 (taker + 1 maker = 2 participants).
- **UTXO selection timing**: Moved UTXO selection (including interactive selector) before orderbook fetch to avoid wasting user time if they cancel.
- **Log verbosity**: Changed fee filtering logs from DEBUG to TRACE to reduce noise.
- **Ignored makers persistence**: Ignored makers list now persists across taker sessions in `~/.joinmarket-ng/ignored_makers.txt`. New CLI command `jm-taker clear-ignored-makers` to clear the list.
- **Blacklisted commitment handling**: Fixed taker to not permanently ignore makers who reject due to a blacklisted commitment. When a maker rejects a commitment as blacklisted, the taker now retries with a different commitment (different NUMS index or UTXO) instead of permanently ignoring that maker. The maker might accept a different commitment, so they should remain available for future attempts.
- **Self-broadcast fallback on already-spent inputs**: Fixed taker broadcast fallback to recognize when a maker has already successfully broadcast the CoinJoin transaction. When self-broadcast fails with "bad-txns-inputs-missingorspent" (UTXOs already spent) or similar errors, the taker now verifies if the CoinJoin transaction exists on-chain before reporting failure. This handles multi-node setups where the maker's broadcast propagates before the taker's verification can confirm it.
- **Wallet history status display**: Fixed `jm-wallet history` to show `[PENDING]` for unconfirmed transactions instead of incorrectly showing `[FAILED]`. Pending transactions (waiting for first confirmation) are now clearly distinguished from actually failed transactions.
- **Wallet info address display**: Fixed `jm-wallet info` to show the next address after the last used one (highest used index + 1) instead of the next unused address. This prevents showing index 0 when higher indexes have been used, making it clear which addresses have been utilized. The display now ignores gaps in the address sequence and always shows the address immediately following the highest used index, considering all usage sources (blockchain history, current UTXOs, and CoinJoin history).

### Added

- **Centralized Version Management**: Introduced a single source of truth for project versioning in `jmcore/src/jmcore/version.py`. All components now import their `__version__` from this central location, ensuring consistency across the project. The version is also accessible via `jmcore.VERSION`, `jmcore.get_version()`, and `jmcore.get_version_info()`.
- **Directory Server Version in MOTD**: Directory servers now advertise the JoinMarket NG version in their MOTD (Message of the Day), similar to the reference implementation. The format is: `JOINMARKET VERSION: X.Y.Z`. This helps clients identify the server software version.
- **Version Bump Script**: New `scripts/bump_version.py` automates the release process by updating all version files, preparing the changelog (adding version header and date, preserving Unreleased section, adding diff link), updating `install.sh`, creating a git commit with a standard message (`release: X.Y.Z`), and tagging. Usage: `python scripts/bump_version.py 0.10.0 --push`
- **Orderbook watcher directory metadata display**: The orderbook watcher web UI now displays directory server metadata including MOTD (message of the day), protocol version (e.g., v5 or v5-6), and supported features (e.g., neutrino_compat, peerlist_features). This information appears in the "Offers per Directory Node" section, helping users understand the capabilities and configuration of each directory server.
- **Interactive UTXO Selection for Taker**: Added `--select-utxos` / `-s` flag to `jm-taker coinjoin` command, enabling interactive UTXO selection before CoinJoin execution. Uses the same fzf-like TUI as `jm-wallet send`, allowing users to manually choose which UTXOs to include in the CoinJoin transaction. Works with both sweep mode and normal CoinJoin mode.
- **Orderbook Response Measurement Tool**: New `scripts/measure_orderbook_delays.py` tool to measure response time distribution when requesting orderbooks from directory servers over Tor. Helps validate timeout settings empirically.
- **Direct Peer Connections**: Taker can now establish direct Tor connections to makers, bypassing directory servers for private message exchange.
  - Improves privacy by preventing directories from observing who is communicating with whom
  - Attempts to establish direct connections before sending `!fill` (5s timeout, no added latency if unavailable)
  - Once a channel is chosen (direct or directory), ALL messages to that maker use the same channel
  - Automatic fallback to directory relay if direct connection fails
  - Connection attempts use exponential backoff to avoid overwhelming peers
  - Enabled by default (`prefer_direct_connections=True` in `MultiDirectoryClient`)
  - New `OnionPeer` class in `jmcore.network` handles direct peer connection lifecycle

- **Maker Replacement on Non-Response**: Taker now automatically replaces non-responsive makers during CoinJoin.
  - New config option: `max_maker_replacement_attempts` (default: 3, range: 0-10)
  - If makers fail to respond during fill or auth phases, taker selects replacements from orderbook
  - Failed makers are added to an ignored list to prevent re-selection
  - Replacement makers go through the full handshake (fill + auth phases)
  - Setting to 0 disables replacement (original behavior: fail immediately)
  - Improves CoinJoin success rate when some makers are unresponsive or drop out

- **Simplified Installation**: New one-line installation with automatic updates.
  - Install: `curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash`
  - Update: `curl -sSL ... | bash -s -- --update`
  - Installs from tagged releases via pip (no git clone required)
  - Creates shell integration at `~/.joinmarket-ng/activate.sh`
  - Unified install/update mode with automatic detection of existing installations

- **Configuration File Support**: Added TOML configuration file (`~/.joinmarket-ng/config.toml`) for persistent settings.
  - Configuration priority: CLI args > environment variables > config file > defaults
  - Auto-generated template with all settings commented out on first run
  - Users only uncomment settings they want to change, facilitating software updates
  - New `config-init` command for maker and taker to initialize the config file
  - Unified settings model in `jmcore.settings` using pydantic-settings

- **Interactive UTXO Selection TUI**: New `--select-utxos` / `-s` flag for `jm-wallet send` command.
  - fzf-like curses interface for manually selecting UTXOs
  - Navigate with arrow keys or j/k, toggle selection with Tab/Space
  - Shows mixdepth, amount (sats and BTC), confirmations, and outpoint
  - Visual indicators for timelocked fidelity bond UTXOs
  - Real-time display of selected total vs target amount
  - Keyboard shortcuts: a (select all), n (deselect all), g/G (top/bottom)

### Changed

- **Renamed `full_node` backend to `scantxoutset`** for clarity. The backend type has been renamed to better reflect what it does (uses Bitcoin Core's `scantxoutset` RPC to scan the UTXO set). This is an alternative backend that should not be recommended for general usage - `descriptor_wallet` is the preferred default for full nodes. Updated all documentation to reflect this change and removed examples about the `scantxoutset` backend from tutorials.
- **Environment Variable Naming Standardization**: Standardized environment variable naming to use double underscore (`__`) for nested settings, following pydantic-settings convention.
  - Old format: `TOR_SOCKS_HOST`, `NOTIFY_URLS`
  - New format: `TOR__SOCKS_HOST`, `NOTIFICATIONS__URLS`
  - Consolidated `TorSettings` and `TorControlSettings` into a single `TorSettings` model
  - Tor control settings now use `TOR__CONTROL_ENABLED`, `TOR__CONTROL_HOST`, `TOR__CONTROL_PORT`, `TOR__COOKIE_PATH`
  - Updated all Docker Compose files to use the new format
  - Config template no longer shows separate `[tor_control]` section (now part of `[tor]`)
- **Installation path**: Virtual environment now lives at `~/.joinmarket-ng/venv/` (was `jmvenv/` in repo)
- **Documentation**: Updated all READMEs to use config file approach instead of .env files
- **Directory connections now parallel**: Taker and orderbook watcher connect to all directory servers concurrently instead of sequentially.
  - Significantly reduces startup time when connecting to multiple directories (especially over Tor).
  - Directory orderbook fetching is also parallelized.
- **Removed peerlist-based offer filtering**: Directory's orderbook is now trusted as authoritative.
  - If a maker has an offer in the directory, they are considered online.
  - Peerlist responses may be delayed or unavailable over Tor, so offers are no longer filtered based on peerlist presence.
  - This prevents incorrectly rejecting valid offers from active makers.
- **Enhanced CoinJoin routing visibility**: Taker now logs detailed message routing information during CoinJoin.
  - Shows which directory servers are used to relay messages to makers.
  - Displays maker onion addresses in the transaction confirmation prompt.
  - Debug logs show routing details for !fill, !auth, !tx, and !push messages.
  - Indicates whether messages are sent via direct connection or directory relay.

## Fixed

- **Wallet Info Shows Next Unused Address**: The `jm-wallet info` command now displays the first unused address (next index after highest used) instead of always showing index 0. This allows users to quickly grab an address for depositing without manual derivation path lookups.
- **Address reuse after internal send**: Fixed address reuse bug where `get_next_address_index` would return an already-used address index after funds were spent.
  - Now properly considers `addresses_with_history` (addresses that ever had UTXOs, including spent ones).
  - Always returns the next index after the highest used, never reusing lower indices even if they appear empty.
  - Prevents privacy leaks from address reuse after internal sends or CoinJoins.
- **Signature base64 padding error**: Fixed "Incorrect padding" errors when decoding maker signatures.
  - Base64 strings without proper padding are now handled correctly.
- **PoDLE commitment blacklist retry**: Taker now automatically retries with a new NUMS index when a maker rejects due to blacklisted commitment.
  - Previously, a blacklisted commitment would cause the entire CoinJoin to fail.
  - Now retries up to `taker_utxo_retries` times (default 3) with different commitment indices.

## [0.9.0] - 2026-01-12

### Added

- **Descriptor Wallet Backend now exposed via CLI**: Users can now select `--backend descriptor_wallet` for fast UTXO tracking.
  - Available in all CLIs: `jm-wallet`, `jm-maker`, `jm-taker`
  - Uses Bitcoin Core's `importdescriptors` for one-time wallet setup
  - Fast syncs via `listunspent` (~1s vs ~90s for scantxoutset)
  - Automatic descriptor import and wallet setup on first use
  - **New default backend** for maker, taker, and wallet commands (changed from `full_node`)
  - Docker compose examples updated to use `descriptor_wallet` by default
- **Orderbook Watcher: Maker direct reachability tracking**.
  - Each offer now includes `directly_reachable` field (true/false/null) showing if maker is reachable via direct Tor connection.
  - Health checker extracts maker features from handshake, useful when directory servers don't provide peerlist features.
  - Reachability info available in orderbook.json API response for monitoring and debugging.
  - Note: Unreachable makers are NOT removed from orderbook - directory may still have valid connection.
- **Operator Notifications**: Push notification system via Apprise for CoinJoin events.
  - Supports 100+ notification services (Gotify, Telegram, Discord, Pushover, email, etc.)
  - Privacy-aware: configurable amount/txid/nick inclusion
  - Per-event toggles for fine-grained control
  - Fire-and-forget: notifications never block protocol operations
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

- **Default backend changed from `scantxoutset` to `descriptor_wallet`** for all components (maker, taker, wallet CLI).
  - Scantxoutset (formerly `full_node`) still available via `--backend scantxoutset`
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
- **Orderbook Watcher peerlist timeout with JoinMarket NG directories**: Fixed incorrect timeout handling when directory announces `peerlist_features` during handshake.
  - Directories announcing `peerlist_features` now use a longer timeout (120s vs 30s) for peerlist requests over Tor.
  - Timeout on directories with `peerlist_features` no longer permanently disables peerlist requests (the peerlist may simply be large and slow to transmit).
  - Improved log messages to distinguish between "likely reference implementation" timeouts and "large peerlist or slow network" timeouts.
- **Orderbook Watcher bond deduplication logging noise**: Fixed false "stale offer replacement" logs when the same offer from the same maker was seen from multiple directories.
  - Same (nick, oid) pairs are now silently deduplicated instead of logging as "stale replacement".
  - Only logs when an actual different maker reuses the same bond UTXO (e.g., after nick restart).
- **Orderbook Watcher aggressive offer pruning**: Fixed overly aggressive cleanup that was removing valid offers.
  - **Removed age-based staleness cleanup entirely** - makers can run for months, offer age is not a valid signal.
  - Maker health check no longer removes offers from makers that are unreachable via direct connection (directory may still have valid connection).
  - Peerlist-based cleanup now skips if any directory refresh fails (avoids false positives).
  - Philosophy changed to **"show offers when in doubt"** rather than aggressive pruning.
  - Only removes offers when explicitly signaled by directory (`;D` disconnect marker or nick absent from ALL directories' peerlists).
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

[Unreleased]: https://github.com/m0wer/joinmarket-ng/compare/0.9.0...HEAD
[0.10.0]: https://github.com/m0wer/joinmarket-ng/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/m0wer/joinmarket-ng/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/m0wer/joinmarket-ng/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/m0wer/joinmarket-ng/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/m0wer/joinmarket-ng/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/m0wer/joinmarket-ng/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/m0wer/joinmarket-ng/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/m0wer/joinmarket-ng/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/m0wer/joinmarket-ng/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/m0wer/joinmarket-ng/releases/tag/0.1.0
