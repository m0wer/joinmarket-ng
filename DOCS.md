# JoinMarket Protocol Documentation

This document consolidates the JoinMarket protocol specification, implementation details, architecture, and testing guide for the modern Python refactored implementation.

## Overview

JoinMarket is a decentralized CoinJoin implementation that allows Bitcoin users to improve their transaction privacy through collaborative transactions.

### How CoinJoin Works

CoinJoin transactions combine multiple users' funds into a single transaction, making it difficult to trace coins. This enhances financial privacy.

The transaction includes several equal amount outputs from inputs belonging to different users. An outside observer cannot determine which input corresponds to which equal amount output, effectively obfuscating the transaction history.

Change outputs are also included, but they are of different amounts and can be easily identified as change and sometimes matched to inputs using heuristics. However, the equal amount outputs remain ambiguous.

One round of CoinJoin increases privacy, but generally multiple rounds are needed to achieve strong anonymity. JoinMarket facilitates this by connecting users who want to mix their coins (takers) with those willing to provide liquidity for a fee (makers).

### Participant Types

- **Makers**: Liquidity providers who offer their UTXOs for CoinJoin and earn fees
- **Takers**: Users who initiate CoinJoins by selecting makers and coordinating the transaction

### What Makes JoinMarket Different

Unlike other CoinJoin implementations (Wasabi, Whirlpool), JoinMarket has **no central coordinator**:

- **Taker acts as coordinator**: Chooses peers, gains maximum privacy (doesn't share inputs/outputs with a centralized party)
- **Most censorship-resistant**: Directory servers are easily replaceable and don't route communications, only host the orderbook
- **Multiple fallbacks**: Works with IRC, Tor hidden services, and can easily move to alternatives like Nostr relays
- **Peer-to-peer**: Direct encrypted communication between participants

### Key Design Principles

1. **Trustless**: No central coordinator; the taker constructs the transaction
2. **Privacy-preserving**: End-to-end encryption for sensitive data
3. **Sybil-resistant**: PoDLE commitments prevent costless DOS attacks
4. **Decentralized**: Multiple redundant directory servers for message routing

### Why Financial Privacy Matters

Just as you wouldn't want your employer to see your bank balance when paying you, or a friend to know your net worth when splitting a bill, Bitcoin users deserve financial privacy. JoinMarket helps individuals exercise their right to financial freedom without promoting illegal activities.

---

## Architecture

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

#### Compatibility & Feature Negotiation

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

#### Roadmap

All components are fully implemented. Future work will focus on improvements, optimizations, and protocol extensions:

- Nostr relays for offer broadcasting
- CoinJoinXT and Lightning Network integration: https://www.youtube.com/watch?v=YS0MksuMl9k

### System Overview

```
                    ┌──────────────────────┐
                    │   Directory Server   │
                    │  (Message Routing)   │
                    └──────────┬───────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
      ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
      │  Maker 1  │      │  Maker 2  │      │   Taker   │
      │           │      │           │      │           │
      │  Wallet   │      │  Wallet   │      │  Wallet   │
      │           │      │           │      │           │
      └─────┬─────┘      └─────┬─────┘      └─────┬─────┘
            │                  │                  │
            └──────────────────┴──────────────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Bitcoin Core / SPV  │
                    │  (Neutrino Option)   │
                    └──────────────────────┘
```

### Component Separation

The implementation separates concerns into distinct packages:

| Package | Purpose |
|---------|---------|
| `jmcore` | Core library: crypto, protocol definitions, models |
| `jmwallet` | Wallet: BIP32/39/84, UTXO management, signing |
| `directory_server` | Directory node: message routing, peer registry |
| `maker` | Maker bot: offer management, CoinJoin participation |
| `taker` | Taker bot: CoinJoin orchestration, maker selection |
| `orderbook_watcher` | Monitoring: orderbook visualization |
| `neutrino_server` (external) | Lightweight SPV server (BIP157/158) - [github.com/m0wer/neutrino-api](https://github.com/m0wer/neutrino-api) |

---

## Data Directory

### Overview

JoinMarket NG uses a dedicated data directory for persistent files that need to be shared across sessions and potentially between maker/taker instances on the same machine.

### Directory Structure

```
~/.joinmarket-ng/          (or $JOINMARKET_DATA_DIR)
├── cmtdata/
│   ├── commitmentlist     PoDLE commitment blacklist (makers, network-wide)
│   └── commitments.json   PoDLE used commitments (takers, local tracking)
├── coinjoin_history.csv   CoinJoin transaction history log
└── fidelity_bonds.json    Fidelity bond registry (addresses, scripts, UTXO info)
```

### Configuration

**Direct Python usage:**
- Default: `~/.joinmarket-ng`
- Override with `--data-dir` CLI flag or `$JOINMARKET_DATA_DIR` environment variable

**Docker usage:**
- Default: `/home/jm/.joinmarket-ng` (mounted as volume)
- Volumes persist across container restarts
- Makers and takers can share volumes for commitment blacklist

**Reference JoinMarket compatibility:**
- To share data with JAM in Docker: `export JOINMARKET_DATA_DIR=/root/.joinmarket`
- The `cmtdata/` subdirectory structure matches JAM's configuration

### Shared Files

**Commitment Blacklist** (`cmtdata/commitmentlist`):
- Used by **makers** to track network-wide blacklisted commitments
- Prevents the same commitment from being accepted by multiple makers
- Synchronized via `!hp2` protocol messages network-wide
- ASCII format: one commitment per line (hex string)

**Used Commitments** (`cmtdata/commitments.json`):
- Used by **takers** to track their own used commitments
- Prevents takers from reusing the same commitment across retries
- JSON format compatible with reference implementation
- Contains `used` array (commitment hashes) and `external` dict (reserved)

**CoinJoin History** (`coinjoin_history.csv`):
- Records all CoinJoin transactions (both pending and confirmed)
- Shared between maker and taker instances
- Tracks fees, roles, peer counts, transaction details, and confirmation status
- **Pending Transaction Tracking**:
  - New transactions are initially marked as pending (`success=False`, `confirmations=0`)
  - Background monitor checks pending transactions every 60 seconds
  - Transactions are marked as successful once they receive their first confirmation
  - Protects against false-positive reporting when inputs are spent by other makers
- **Maker Transaction ID Discovery**:
  - Makers may not initially know the final transaction ID (`txid`) when creating history entries
  - By default, takers only send the full signed transaction (`!push`) to one random maker
  - Other participating makers sign the transaction but don't receive the final txid
  - History entries without txid are marked as pending until discovered
  - **Automatic Discovery**: After restart and wallet rescan, makers discover the txid by:
    1. Checking if their CoinJoin destination address received funds
    2. Matching the UTXO's txid to the pending history entry
    3. Updating the history with the discovered txid and checking confirmations
  - **Address Privacy Protection**: Once shared with peers, **both** CoinJoin destination and change addresses are permanently blacklisted from reuse, even if:
    - The transaction was never confirmed
    - The maker doesn't know the txid
    - The CoinJoin failed for any reason
  - Wallet automatically skips address indices that would generate blacklisted addresses during CoinJoin
  - **UTXO Reuse**: Makers can immediately reuse their input UTXOs in new CoinJoins without waiting for confirmation (history tracking is independent of UTXO availability)
- CSV format for easy analysis with external tools
- View with: `jm-wallet history --stats` or `jm-wallet history --limit 10`

### Periodic Wallet Rescan

Both maker and taker support periodic wallet rescanning to detect balance changes from external sources (deposits, spends via Sparrow, etc.) and confirm pending transactions.

**Configuration:**

| Setting | Default | Description |
|---------|---------|-------------|
| `rescan_interval_sec` | 600 (10 min) | How often to rescan the wallet |
| `post_coinjoin_rescan_delay` | 60 | Seconds to wait after CoinJoin before rescanning (maker only) |

**Maker Behavior:**
- After a CoinJoin, waits `post_coinjoin_rescan_delay` (default: 60s) before rescanning
- This delay allows the transaction to propagate in the mempool before scanning
- If the max balance across mixdepths changes, offers are automatically recreated and re-announced
- Periodic rescans every `rescan_interval_sec` also trigger offer updates if balance changed
- This enables "set and forget" maker operation - balance changes are handled automatically

**Taker Behavior:**
- Periodic rescans update wallet state between schedule/tumbler entries
- Pending transaction monitor updates confirmation status

**Use Cases:**
- Maker can run in background while user does manual transactions from Sparrow
- After external deposits, maker automatically updates offer maxsize
- After a CoinJoin, confirmation is tracked without manual intervention

---

## Configuration File

JoinMarket NG supports a TOML configuration file for centralized settings management across all components.

### Overview

Configuration is loaded with the following priority (highest to lowest):
1. **CLI arguments** - Command-line options override everything
2. **Environment variables** - Override config file settings
3. **Config file** (`~/.joinmarket-ng/config.toml`) - Persistent settings
4. **Built-in defaults** - Used when no override is specified

This design allows users to set base configuration in the file while easily overriding specific values via environment or CLI for different scenarios.

### Config File Location

- Default: `~/.joinmarket-ng/config.toml`
- Override with: `$JOINMARKET_DATA_DIR/config.toml` or `$JOINMARKET_CONFIG_FILE`

### Auto-Generation

On first run, the config file is automatically created with all settings commented out. This approach:
- Shows all available settings with descriptions
- Documents default values
- Allows users to selectively uncomment and modify only what they need
- Facilitates software updates (unchanged defaults are updated automatically)

### Environment Variable Mapping

Environment variables use uppercase with double underscore (`__`) for nested settings:

| Config File | Environment Variable |
|-------------|---------------------|
| `[tor]` `socks_host` | `TOR__SOCKS_HOST` |
| `[bitcoin]` `rpc_url` | `BITCOIN__RPC_URL` |
| `[maker]` `min_size` | `MAKER__MIN_SIZE` |

### Configuration Sections

| Section | Description |
|---------|-------------|
| `[tor]` | Tor SOCKS proxy and control port settings |
| `[bitcoin]` | Bitcoin backend settings (RPC, Neutrino) |
| `[network]` | Protocol network and directory servers |
| `[wallet]` | HD wallet structure settings |
| `[notifications]` | Push notification settings |
| `[logging]` | Log level and options |
| `[maker]` | Maker-specific settings |
| `[taker]` | Taker-specific settings |
| `[directory_server]` | Directory server settings |
| `[orderbook_watcher]` | Orderbook watcher settings |

### Example Config

```toml
# ~/.joinmarket-ng/config.toml

[tor]
socks_host = "tor"  # Docker service name
socks_port = 9050

[bitcoin]
backend_type = "descriptor_wallet"
rpc_url = "http://bitcoind:8332"
rpc_user = "jm"
rpc_password = "secret"

[network]
network = "signet"

[notifications]
urls = ["gotify://your-server.com/token"]
include_txids = false

[maker]
min_size = 50000
cj_fee_relative = "0.002"
merge_algorithm = "gradual"
```

### CLI Commands

```bash
# Initialize config file with template
jm-maker config-init

# View current config path
echo $JOINMARKET_DATA_DIR/config.toml
```

---

## Dependency Management

We use pip-tools for pinned dependencies and reproducible builds:

- **Install**: `jmcore` → `jmwallet` → other packages (in order)
- **Update**: Run `./scripts/update-deps.sh` to update all packages
- **Development**: Install `-r requirements-dev.txt` after production deps

See individual package READMEs for setup details.

---

## Wallet & UTXO Management

JoinMarket uses BIP32 HD wallets with a privacy-focused structure based on **mixdepths** and intelligent UTXO selection.

### Wallet Structure

HD path: `m/84'/0'/0'/mixdepth/chain/index` (P2WPKH Native SegWit)

**Mixdepths (Default: 5 isolated accounts)**:
- Inputs for a CoinJoin come from a **single mixdepth**
- CoinJoin outputs go to the **next mixdepth** (wrapping 4 → 0)
- Change outputs stay in the **same mixdepth**

This prevents merging CoinJoin outputs with their change, blocking trivial linkage.

**Address Branches** (per mixdepth):
- **External (0)**: Receiving addresses
- **Internal (1)**: Change addresses

Example:
```
mixdepth 0/external: m/84'/0'/0'/0/0/0 → bc1q... (receive)
mixdepth 0/internal: m/84'/0'/0'/0/1/0 → bc1q... (change)
mixdepth 1/external: m/84'/0'/0'/1/0/0 → bc1q... (CJ output from mixdepth 0)
```

### BIP39 Passphrase Support

JoinMarket NG supports the optional BIP39 passphrase (also known as the "13th word" for 12-word mnemonics or "25th word" for 24-word mnemonics). This allows deriving different wallets from the same mnemonic phrase.

**Important Distinction**:

- **File encryption password** (`--password`): Encrypts the mnemonic file on disk with AES
- **BIP39 passphrase** (`--bip39-passphrase`): Used in seed derivation per BIP39 spec

**Wallet Import vs. Usage**:

The `jm-wallet import` command only stores the 12/24-word mnemonic - it does NOT take a BIP39 passphrase. This is intentional because the passphrase is used at key derivation time, not at storage time.

```bash
# Import only stores the mnemonic (no BIP39 passphrase here)
jm-wallet import --words 24

# BIP39 passphrase is provided when USING the wallet:
jm-wallet info --prompt-bip39-passphrase       # Interactive prompt
jm-wallet info --bip39-passphrase "my phrase"  # CLI argument
BIP39_PASSPHRASE="my phrase" jm-wallet info    # Environment variable
```

**Use Cases**:

- Migrate existing wallets with passphrases (e.g., from other implementations)
- Derive multiple wallets from one mnemonic for different purposes
- Plausible deniability (different passphrase → different wallet)

**Security Notes**:

- Empty passphrase (`""`) is valid and different from no passphrase
- Passphrase is case-sensitive and whitespace-sensitive
- Lost passphrase = lost access to that wallet derivation
- For fidelity bonds: Same passphrase must be used for bond creation and redemption

### No BerkeleyDB Requirement

Reference implementation requires Bitcoin Core wallet (BerkeleyDB). Bitcoin Core v30+ removed BDB support.

**Our solution**: Use `scantxoutset` RPC directly (no wallet needed) + Neutrino SPV support.

### UTXO Selection

**Taker Selection**:
- **Normal**: Minimum UTXOs to cover `cj_amount + fees`
- **Sweep** (`--amount=0`): All UTXOs, zero change output (best privacy)

```bash
# Sweep mode (maximum privacy)
jm-taker coinjoin --amount=0 --mixdepth=0 --destination=INTERNAL
```

**Maker Merge Algorithms** (takers pay fees, so makers can consolidate):

| Algorithm | Behavior |
|-----------|----------|
| `default` | Minimum UTXOs only |
| `gradual` | Minimum + 1 small UTXO |
| `greedy` | All UTXOs from mixdepth |
| `random` | Minimum + 0-2 random UTXOs |

```bash
jm-maker start --merge-algorithm=greedy
```

Privacy tradeoff: More inputs = faster consolidation but reveals UTXO clustering.

---

## Backend Systems

JoinMarket NG supports three blockchain backends with different tradeoffs:

### Descriptor Wallet Backend (Recommended)

- **Method**: `importdescriptors` + `listunspent` RPC
- **Requirements**: Bitcoin Core v24+
- **Validation**: Full validation
- **Storage**: ~900 GB (full node) + small wallet file
- **Privacy**: High (local node)
- **Sync Speed**: Fast after initial descriptor import

Uses Bitcoin Core's descriptor wallet feature to persistently track addresses. After one-time descriptor import, subsequent syncs use `listunspent` which is O(wallet UTXOs) instead of scanning the entire UTXO set. Provides mempool awareness and real-time balance updates.

Trade-off: Wallet files persist on disk on the node. Funds are not at risk, but all your addresses are stored in the node's wallet. So never use this with a third-party node.

**Smart Scan for Fast Startup**: By default, descriptor import uses "smart scan" which only scans the blockchain from approximately 1 year ago (52,560 blocks). This allows fast startup on mainnet (seconds instead of 20+ minutes). A full background rescan from genesis is triggered automatically to ensure no old transactions are missed.

Configuration options in `WalletConfig`:
- `smart_scan: bool = True` - Use fast startup with partial scan
- `background_full_rescan: bool = True` - Trigger full rescan in background
- `scan_lookback_blocks: int = 52_560` - How far back to scan initially (~1 year)

### Bitcoin Core Backend (Legacy)

- **Method**: `scantxoutset` RPC (no wallet required)
- **Requirements**: Bitcoin Core v30+
- **Validation**: Full validation
- **Storage**: ~900 GB
- **Privacy**: High (local node)
- **Sync Speed**: Slow (~90s per scan on mainnet)

Scans the entire UTXO set each time. Useful for one-off operations where persistent tracking isn't needed.

### Neutrino Backend

- **Method**: BIP157/158 compact block filters
- **Requirements**: [neutrino-api server](https://github.com/m0wer/neutrino-api) (Go)
- **Validation**: Headers + filters
- **Storage**: ~500 MB
- **Privacy**: High (downloads filters, not addresses)
- **Sync**: Minutes instead of days

**Decision Matrix**:
- Use DescriptorWalletBackend if: You run a full node and want fast ongoing operations (recommended)
- Use BitcoinCoreBackend if: You need simple one-off UTXO queries without wallet setup
- Use Neutrino if: Limited storage, fast setup, light client needed



### Transaction Verification

After broadcasting, takers verify the transaction was accepted:

- **Core/Mempool backends**: Use `get_transaction(txid)` to check mempool/chain
- **Neutrino backend**: Cannot access mempool. See "Neutrino Broadcast Strategy" below.

Both spent and unspent responses confirm broadcast success.

### Neutrino Broadcast Strategy

Neutrino clients using BIP157/158 compact block filters **cannot access the mempool**.
This affects transaction broadcast verification, but the taker uses the same broadcast
policies as full nodes with appropriate adaptations:

**Problem**: After sending `!push` to a maker, Neutrino cannot verify if the transaction
is in the mempool. Full nodes can check `get_transaction(txid)` but Neutrino must wait
for block confirmation.

**Solution**: All broadcast policies work the same way for both full nodes and Neutrino:

| Policy | Behavior (Full Node & Neutrino) |
|--------|--------------------------------|
| `SELF` | Broadcast via own backend (always verifiable) |
| `RANDOM_PEER` | Try makers sequentially in random order, fall back to self as last resort |
| `MULTIPLE_PEERS` | Broadcast to N random makers simultaneously (default N=3), fall back to self if all fail |
| `NOT_SELF` | Try makers sequentially, never self. No fallback if all fail |

**Default policy**: `MULTIPLE_PEERS` (recommended for both full node and Neutrino)

**Multi-peer broadcast**: Instead of trying one maker at a time, `MULTIPLE_PEERS` sends
`!push` to N random makers simultaneously (default 3). This provides redundancy without
broadcasting to all makers, reducing network footprint.

**Privacy note**: All makers already participated in the CoinJoin, so they all know
the transaction. Sending `!push` to multiple makers doesn't reveal new information.

**Self-fallback for Neutrino**: When Neutrino falls back to self-broadcast, it cannot
verify the transaction is in the mempool. It trusts that `broadcast_transaction()`
succeeded based on the backend's response. Confirmation is verified later via block-based
UTXO lookups.

**Confirmation monitoring**: Pending transactions are monitored using `verify_tx_output()`
with the destination address hint, checking if the CoinJoin output appears in confirmed blocks.

### Directory Server Transport Protocol

All messages use JSON-line envelopes terminated with `\r\n`:

```json
{"type": <message_type>, "line": "<payload>"}
```

This is the **transport layer** - it wraps the actual JoinMarket protocol messages.

#### Message Types

| Code | Name | Description |
|------|------|-------------|
| 685 | PRIVMSG | Private message between two peers |
| 687 | PUBMSG | Public broadcast to all peers |
| 789 | PEERLIST | Directory sends list of connected peers |
| 791 | GETPEERLIST | Request peer list from directory |
| 793 | HANDSHAKE | Client handshake request |
| 795 | DN_HANDSHAKE | Directory handshake response |
| 797 | PING | Keep-alive ping |
| 799 | PONG | Ping response |
| 801 | DISCONNECT | Graceful disconnect |

### JoinMarket Protocol Messages (Inside Transport)

Inside the `line` field of PRIVMSG/PUBMSG, JoinMarket messages follow this format:

```
!command [[field1] [field2] ...]
```

For private messages, the format includes routing information:

```
{from_nick}!{to_nick}!{command} {arguments}
```

- `from_nick`: Sender's nickname (e.g., `J6AiXEVUkwBBZs8A`)
- `to_nick`: Recipient or `PUBLIC` for broadcasts
- `command`: Command with `!` prefix
- `arguments`: Fields separated by **single whitespace** (more than one space not allowed)

### Message Routing: Directory Relay vs Direct Connections

JoinMarket supports two routing modes for private messages:

#### Direct Peer Connections (Preferred)

Our implementation opportunistically establishes direct Tor connections to makers, bypassing directory servers for private message exchange. This is the default behavior (`prefer_direct_connections=True`).

1. Taker receives maker onion addresses from directory (`!peerlist` or handshake)
2. When taker wants to message a maker:
   - Check if direct connection exists
   - If not, **try to connect directly** to maker's onion address (async)
   - Fall back to directory relay if direct connection fails
3. Once connected, future messages sent directly peer-to-peer

**Protocol Details**:
- **Handshake**: Direct connections use a specific handshake format matching the reference implementation: `{"type": 793, "line": "<json>"}`.
- **Signing**: Messages sent via direct connection must include a signature where the `hostid` is set to `onion-network`. This differs from directory routing where `hostid` is the directory's onion address.
- **Identity**: The `nick_identity` parameter is used to verify the peer's identity matches their public key.

**Advantages**:
- **Privacy**: Directory server cannot observe message metadata (timing, frequency, recipients).
- **Performance**: Lower latency for subsequent messages (no relay hop).
- **Scalability**: Reduces load on directory servers.

**Tradeoffs**:
- Requires Tor circuit establishment (initial latency).
- Requires makers to have reachable onion services.

#### Directory Relay (Fallback)

If direct connections cannot be established (e.g., maker behind firewall, Tor issues), messages are automatically routed through directory servers:

1. Taker sends `PRIVMSG` to directory: `{taker_nick}!{maker_nick}!fill ...`
2. Directory forwards to maker (if connected to same directory)
3. Maker responds via `PRIVMSG` through directory

**Advantages**:
- **Reliability**: Works even if peers cannot directly reach each other (e.g. restrictive firewalls).
- **Simplicity**: No NAT traversal or hidden service management needed on client side.

**Tradeoffs**:
- Directory sees message metadata (sender, recipient, timing).
- Higher latency (extra hop).
- Messages duplicated to all directories in multi-directory setup.

**Implementation Status**:
- **Direct Connections**: Enabled by default in `MultiDirectoryClient`. Automatic fallback to directory relay.
- **Directory Relay**: Used for initial messages and as reliable fallback.


#### Multi-part Messages

- Unencrypted messages may contain multiple commands
- Split on command prefix (`!`)
- Currently used for `!reloffer` and `!absoffer` commands
- **NOT allowed for encrypted messages** (single command only)

### Nick Format

Nicks are derived from ephemeral keypairs:

```
J + version + base58(sha256(pubkey)[:NICK_HASH_LEN])
```

**Construction details**:
- `NICK_HASH_LEN`: 14 bytes of sha256 hash
- Right-padded with 'O' if `< NICK_MAX_ENCODED` (currently not needed)
- Current format: 16 chars total (1 type + 1 version + 14 pubkey-hash)
- Encoding: Base58 (not Base58Check - no checksum)

Example: `J54JdT1AFotjmpmH` (16 chars total, v5 peer)

The nick format enables:
1. Anti-spoofing via message signatures
2. Nick recovery across multiple message channels

**Note**: Our implementation uses J5 nicks for compatibility with the reference implementation. All feature detection (like `neutrino_compat`) happens via handshake features, not nick version.

#### Anti-Replay Protection

All private messages include `<pubkey> <signature>` fields for authentication. The signed plaintext is:

```
message + hostid
```

Where:
- `message`: The actual message content
- `hostid`: Unique identifier for this MessageChannel (e.g., directory server address)

This prevents replaying the same signature across different message channels, ensuring that a valid signature on one directory server cannot be reused on another.

---

## Reference Implementation Compatibility

This section documents protocol compatibility findings between our implementation and the reference JoinMarket implementation ([joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver/)).

### Orderbook Request Behavior

**Reference implementation behavior**: When a peer sends `!orderbook` via PUBMSG, makers respond with offers via **PRIVMSG** (directly to the requesting peer), not PUBMSG.

**Implications for clients**: The `listen_continuously()` function must process both PUBMSG and PRIVMSG message types to receive offer responses. Processing only PUBMSG will miss offer responses.

### Stale Offer Filtering

**Problem**: Makers may disconnect between orderbook fetch and CoinJoin execution, leaving stale offers that will timeout when contacted.

**Solution**: The `fetch_orderbooks()` method filters offers against the current peerlist to ensure only offers from currently connected makers are returned:

1. Fetch peerlist with features (`get_peerlist_with_features()`)
2. If empty, fall back to basic peerlist (`get_peerlist()`) for reference implementation compatibility
3. Collect offers from `!orderbook` broadcast responses
4. Filter offers to only include those from makers in the current peerlist
5. Log warnings when stale offers are filtered out

**Benefits**:
- Prevents timeouts from selecting disconnected makers
- Works with both feature-aware and legacy directory servers
- Gracefully handles regtest/NOT-SERVING-ONION environments where peerlist may be empty

### Multi-Directory Nick Tracking

**Problem**: In multi-directory setups, a maker may temporarily disconnect from one directory while remaining connected to others. Naive implementations might prematurely mark the maker as "gone" and ignore their offers.

**Solution**: The `MultiDirectoryClient` implements multi-directory aware nick tracking - a nick is only considered "gone" when ALL connected directories report it as disconnected.

**Implementation**:
- Format: `active_nicks[nick] = {server1: True, server2: False, ...}`
- A nick is active if at least one server reports `True`
- The `on_nick_leave` callback only fires when ALL servers report the nick as gone
- Prevents premature maker removal during network flakiness or directory-specific connection issues

**Reference**: JoinMarket `onionmc.py` lines 1078-1103

**Benefits**:
- Improves maker availability in multi-directory environments
- Reduces false positives from temporary connection issues
- Handles directory-specific disconnections gracefully
- Compatible with flaky Tor connections

The standalone `NickTracker` class (`jmcore/nick_tracker.py`) can be used by any component needing multi-directory awareness (makers, takers, orderbook watchers).

### Peerlist Format

The peerlist response may contain metadata entries that don't follow the standard `nick;location` format:

**Standard entries**:
```
nick1;host1.onion:5222
nick2;host2.onion:5222;D
```

**Metadata entries** (reference implementation):
```
peerlist_features  # No semicolon separator
```

**Handling**: Clients should skip entries without the `;` separator rather than treating them as parse errors.

### GETPEERLIST Support

The reference implementation directory server may not respond to `GETPEERLIST` requests within typical timeouts. Clients should:
1. Handle timeout gracefully
2. Fall back to receiving peerlist updates via the initial handshake response
3. Listen for peerlist updates broadcast during normal operation

### Known Directory Servers

| Network | Type | Address |
|---------|------|---------|
| Mainnet | Reference | `jmarketxf5wc4aldf3slm5u6726zsky52bqnfv6qyxe5hnafgly6yuyd.onion:5222` |
| Mainnet | JM-NG | `jmv2dirze66rwxsq7xv7frhmaufyicd3yz5if6obtavsskczjkndn6yd.onion:5222` |

---

## Feature Flags System

### Overview

This implementation uses **feature flags** instead of protocol version bumps to enable progressive capability adoption while maintaining full backward compatibility with the reference JoinMarket implementation.

### Design Philosophy

**Why feature flags instead of version bumps?**

1. **Backward Compatibility**: The reference implementation from [joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver/) only accepts `proto-ver=5`. Version bumps would break interoperability.
2. **Granular Adoption**: Features can be adopted independently without forcing "all or nothing" upgrades.
3. **Progressive Enhancement**: Peers advertise what they support; both sides negotiate capabilities per-session.

### Protocol Version

```
JM_VERSION = 5  (matches reference implementation)
```

We maintain v5 for full compatibility. New capabilities are negotiated via feature flags, not version changes.

### Feature Detection

Features are detected through the **handshake features dict**. During CoinJoin sessions, makers advertise features in their `!pubkey` response (e.g., `features=neutrino_compat`).

This approach ensures:
- **Smooth rollout**: No network-wide upgrades required
- **Backwards compatibility**: Legacy peers ignore unknown fields
- **No version fragmentation**: All peers use protocol v5

### Available Features

| Feature | Description |
|---------|-------------|
| `extended_peerlist` | Supports extended peerlist format with feature flags in `F:` field |
| `neutrino_compat` | Supports extended UTXO format with scriptPubKey and blockheight |

#### Extended Peerlist

The `extended_peerlist` feature flag enables peers to advertise their capabilities through the peerlist format.

**Format**: `nick;location;F:feature1+feature2`

When both directory server and peer support `extended_peerlist`:
1. Peer advertises features in handshake
2. Directory server includes features in peerlist responses
3. Peers can filter orderbook by required features before initiating CoinJoin

**Compatibility**: Peers without `extended_peerlist` receive standard `nick;location` format.

#### Neutrino Compatibility

The `neutrino_compat` feature flag enables Neutrino backends by extending UTXO metadata.

**Problem**: Neutrino can't verify arbitrary UTXOs (only addresses it watches). CoinJoin needs to verify peer UTXOs.

**Solution**: Extended UTXO format includes scriptPubKey + block height:

| Format | Example |
|--------|---------|
| Legacy | `txid:vout` |
| Extended | `txid:vout:scriptpubkey:height` |

When both peers support `neutrino_compat`:
1. UTXO metadata included in `!auth` and `!ioauth` messages
2. Neutrino backend adds scriptPubKey to watch list
3. Rescans from block height to verify UTXO exists

**Compatibility**: Neutrino takers filter out makers without `neutrino_compat` flag.

### FeatureSet Implementation

```python
from jmcore.protocol import FeatureSet, FEATURE_NEUTRINO_COMPAT, FEATURE_EXTENDED_PEERLIST

# Create feature set
features = FeatureSet(features={FEATURE_EXTENDED_PEERLIST, FEATURE_NEUTRINO_COMPAT})

# Check support
if features.supports_extended_peerlist():
    # Use extended peerlist format with F: field
    pass

if features.supports_neutrino_compat():
    # Use extended UTXO format
    pass

# Serialize for handshake
features_dict = features.to_dict()  # {"extended_peerlist": True, "neutrino_compat": True}
```

### Handshake Integration

**Handshake Request** (peer → directory):
```json
{
  "proto-ver": 5,
  "features": {"extended_peerlist": true, "neutrino_compat": true},
  ...
}
```

**Handshake Response** (directory → peer):
```json
{
  "proto-ver-min": 5,
  "proto-ver-max": 5,
  "features": {"extended_peerlist": true, "neutrino_compat": true},
  ...
}
```

**Note**: The `features` dict is ignored by the reference implementation but preserved for our peers.

### Extended Peerlist Format

Our implementation extends the peerlist format to include feature flags:

```
nick;location;F:feature1+feature2
```

**Important**: The feature separator is `+` (plus), not `,` (comma), because the peerlist itself uses commas to separate entries. Using commas for features would cause parsing ambiguity:

```
# WRONG: Commas cause ambiguity
nick1;host.onion:5222;F:feat1,feat2,nick2;host2.onion:5222
# Parser cannot distinguish feature "feat2" from entry "nick2;host2.onion:5222"

# CORRECT: Plus separator avoids ambiguity
nick1;host.onion:5222;F:feat1+feat2,nick2;host2.onion:5222
# Clear separation: entry 1 has features "feat1" and "feat2", entry 2 starts at "nick2"
```

The `F:` prefix identifies the features field and maintains backward compatibility with legacy clients that don't understand the extension.

---

## Operator Notifications

JoinMarket NG supports push notifications for CoinJoin events via [Apprise](https://github.com/caronc/apprise), enabling alerts through 100+ services including Gotify, Telegram, Discord, Pushover, and email.

### Installation

Notifications are an optional feature but `apprise` is installed by default.

```bash
pip install jmcore
# or
pip install apprise>=1.8.0
```

### Configuration

Configuration can be set via config file (`~/.joinmarket-ng/config.toml`) or environment variables.

**Environment variables** (use JSON array format for `urls`):

| Variable | Default | Description |
|----------|---------|-------------|
| `NOTIFICATIONS__URLS` | `[]` | JSON array of Apprise URLs (required to enable) |
| `NOTIFICATIONS__ENABLED` | `false` | Set `true` to enable (auto-enabled if URLs provided) |
| `NOTIFICATIONS__TITLE_PREFIX` | `JoinMarket NG` | Prefix for notification titles |

**Privacy settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `NOTIFICATIONS__INCLUDE_AMOUNTS` | `true` | Include satoshi amounts in notifications |
| `NOTIFICATIONS__INCLUDE_TXIDS` | `false` | Include transaction IDs (privacy risk) |
| `NOTIFICATIONS__INCLUDE_NICK` | `true` | Include peer nicks (full, not truncated) |

**Tor/Proxy settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `NOTIFICATIONS__USE_TOR` | `true` | Route notifications through Tor SOCKS proxy |

When enabled, notifications use `TOR__SOCKS_HOST` and `TOR__SOCKS_PORT` environment variables (defaults: `127.0.0.1:9050`).

**Per-event toggles:**

| Variable | Default | Component | Description |
|----------|---------|-----------|-------------|
| `NOTIFICATIONS__FILL` | `true` | Maker | Notify on !fill requests |
| `NOTIFICATIONS__REJECTION` | `true` | Maker | Notify on rejections |
| `NOTIFICATIONS__SIGNING` | `true` | Maker | Notify on TX signing |
| `NOTIFICATIONS__MEMPOOL` | `true` | Both | Notify when CJ in mempool |
| `NOTIFICATIONS__CONFIRMED` | `true` | Both | Notify on confirmation |
| `NOTIFICATIONS__NICK_CHANGE` | `true` | Maker | Notify on nick change |
| `NOTIFICATIONS__DISCONNECT` | `true` | Maker | Notify on directory disconnect |
| `NOTIFICATIONS__COINJOIN_START` | `true` | Taker | Notify on CoinJoin start |
| `NOTIFICATIONS__COINJOIN_COMPLETE` | `true` | Taker | Notify on CoinJoin complete |
| `NOTIFICATIONS__COINJOIN_FAILED` | `true` | Taker | Notify on CoinJoin failure |
| `NOTIFICATIONS__PEER_EVENTS` | `false` | Directory | Notify on peer connect/disconnect |
| `NOTIFICATIONS__RATE_LIMIT` | `true` | Directory | Notify on rate limit bans |
| `NOTIFICATIONS__STARTUP` | `true` | All | Notify on component startup |

**Config file** (`config.toml` uses native TOML arrays):

```toml
[notifications]
urls = ["gotify://your-server.com/token", "tgram://bot/chat"]
include_amounts = true
include_txids = false
include_nick = true
use_tor = true

# Per-event toggles
notify_fill = true
notify_rejection = true
notify_signing = true
notify_mempool = true
notify_confirmed = true
# ... (see environment variables above for all options)
```

### Example URLs

```bash
# Gotify (self-hosted)
export NOTIFICATIONS__URLS='["gotify://your-server.com/AaBbCcDdEeFf"]'

# Telegram
export NOTIFICATIONS__URLS='["tgram://bot_token/chat_id"]'

# Discord webhook
export NOTIFICATIONS__URLS='["discord://webhook_id/webhook_token"]'

# Multiple services (JSON array)
export NOTIFICATIONS__URLS='["gotify://host/token", "tgram://bot/chat"]'

# Email
export NOTIFICATIONS__URLS='["mailto://user:pass@smtp.example.com"]'
```

See [Apprise documentation](https://github.com/caronc/apprise#supported-notifications) for 100+ supported services.

### Docker Usage

```yaml
services:
  maker:
    image: joinmarket-ng/maker
    environment:
      - NOTIFICATIONS__URLS=["gotify://your-server.com/token"]
      - NOTIFICATIONS__INCLUDE_TXIDS=false
```

---

## CoinJoin Protocol Flow

All protocol commands use JSON-line format: `{"type": <code>, "line": "<payload>"}\r\n`

### Protocol Commands

| Command | Encrypted | Plaintext OK | Phase | Description |
|---------|-----------|--------------|-------|-------------|
| `!orderbook` | No | ✓ | 1 | Request offers from makers |
| `!reloffer`, `!absoffer` | No | ✓ | 1 | Maker offer responses (via PRIVMSG) |
| `!fill` | No | ✓ | 2 | Taker fills offer with NaCl pubkey + PoDLE commitment |
| `!pubkey` | No | ✓ | 2 | Maker responds with NaCl pubkey |
| `!error` | No | ✓ | Any | Error notification |
| `!push` | No | ✓ | 5 | Request maker to broadcast transaction |
| `!tbond` | No | ✓ | 1 | Fidelity bond proof (with offers) |
| `!auth` | **Yes** | ✗ | 3 | Taker reveals PoDLE proof (encrypted) |
| `!ioauth` | **Yes** | ✗ | 3 | Maker sends UTXOs + addresses (encrypted) |
| `!tx` | **Yes** | ✗ | 4 | Taker sends unsigned transaction (encrypted) |
| `!sig` | **Yes** | ✗ | 4 | Maker signs inputs (encrypted, one per input) |

**Note**: Rules enforced at message_channel layer. All encrypted messages are base64-encoded.

### Phase 1: Orderbook Discovery

Taker broadcasts `!orderbook` via PUBMSG. Makers respond with offers via PRIVMSG (not PUBMSG).

**Offer Format**: Offers use format `!sw0reloffer <oid> <minsize> <maxsize> <txfee> <cjfee>` where:
- `oid`: Order ID (integer)
- `minsize`: Minimum CoinJoin amount in satoshis
- `maxsize`: Maximum CoinJoin amount in satoshis
- `txfee`: **Total transaction fee contribution in satoshis** (not per-input/output)
- `cjfee`: Relative fee (0.0-1.0) for relative offers, or absolute fee in satoshis for absolute offers

The `txfee` field represents the maker's total contribution to the mining fee, which is deducted from their change output. This is a fixed amount regardless of the number of inputs/outputs the maker contributes. It's kept for historical reasons, but there are currently no offers on the orderbook with non-zero `txfee`.

### Maker Selection Algorithm

After collecting offers, the taker selects makers through three phases:

**Phase 1 - Filtering**: Remove offers that don't meet criteria (amount range, fee limits, offer type, ignored makers).

**Phase 2 - Deduplication**: **If a maker advertises multiple offers under the same nick, only the cheapest offer is kept.** This ensures makers cannot game selection by flooding the orderbook.

**Phase 3 - Selection**: Choose `n` makers from the deduplicated list using one of these algorithms:

| Algorithm | Behavior |
|-----------|----------|
| `fidelity_bond_weighted` (default) | Mixed strategy: round(n × 87.5%) slots filled by bond-weighted selection, remaining slots filled randomly from all offers (bonded or bondless). "Bondless" means bond-agnostic, giving equal opportunity to all makers regardless of bond status. |
| `cheapest` | Lowest fee first |
| `weighted` | Exponentially weighted by inverse fee |
| `random` | Uniform random selection |

**Key Point**: Selection probability is proportional to the **maker identity (nick)**, not the number of offers. A maker with 5 offers has the **same selection probability** as a maker with 1 offer (assuming both pass filters). The deduplication phase ensures fairness.

Implementation: `taker/src/taker/orderbook.py` (`filter_offers`, `dedupe_offers_by_maker`, `choose_orders`)

### Maker Replacement on Non-Response

When makers fail to respond during a CoinJoin, the taker can automatically select replacement makers from the orderbook instead of aborting the entire CoinJoin.

**Configuration**: `max_maker_replacement_attempts` (default: 3, range: 0-10)
- Set to 0 to disable (original behavior: abort on first failure)
- Set to 1-10 to enable automatic replacement

**Behavior**:
1. **Fill Phase Failure**: If makers don't respond to `!fill` with `!pubkey`:
   - Failed makers added to ignored list (excluded from future selection)
   - Taker selects replacement makers from orderbook
   - Sends `!fill` to replacement makers
   - Continues once enough makers have responded

2. **Auth Phase Failure**: If makers don't respond to `!auth` with `!ioauth`:
   - Failed makers added to ignored list
   - Taker selects replacement makers from orderbook
   - New makers go through fill phase (`!fill` → `!pubkey`)
   - Then all makers (original + replacements) continue to auth phase
   - Continues once enough makers have sent UTXOs

**Limits**:
- Maximum `max_maker_replacement_attempts` retries per phase
- Replacement makers must pass same filters as original selection (fee limits, amount range, etc.)
- If not enough replacement makers available, CoinJoin aborts
- Failed makers remain ignored for the entire CoinJoin session

**Example**: With `minimum_makers=2` and `max_maker_replacement_attempts=3`:
- Select 3 makers: A, B, C
- Fill phase: A and B respond, C times out
- Replacement attempt 1: Select D from orderbook, D responds
- Auth phase: A responds, B and D timeout
- Replacement attempt 1: Select E and F from orderbook
- Fill phase (for E, F): Both respond
- Auth phase (for A, E, F): A and E respond, F times out
- Replacement attempt 2: Select G from orderbook
- Eventually succeed with A, E, G

Implementation: `taker/src/taker/taker.py` (`PhaseResult`, `do_coinjoin`)

### Phase 2: Fill Request


Taker sends `!fill <oid> <amount> <taker_nacl_pk> <commitment>`. Maker responds with `!pubkey <maker_nacl_pk> <signing_pk> <sig>`.

After key exchange, a NaCl `Box` is created for authenticated encryption.

#### Message Encryption Sequence

For encrypted messages, the sequence is:
1. Plaintext message → Encryption (NaCl Box)
2. Encrypted bytes → Base64 encoding
3. Add `!command` prefix to Base64 string
4. Send as private message

Receiving is the reverse process:
1. Extract Base64 payload (after `!command` prefix)
2. Base64 decode → Encrypted bytes
3. NaCl Box decryption → Plaintext message

### Phase 3: Authentication (Encrypted)

Taker sends `!auth` with encrypted PoDLE revelation. Fields are **pipe-separated** (`|`):

```
!auth U|P|P2|s|e
```

Where:
- `U`: UTXO in format `txid:vout` (or `txid:vout:spk:height` with `neutrino_compat`)
- `P`: Public key
- `P2`: Commitment point
- `s`: Signature
- `e`: Exponent

Maker verifies PoDLE, then sends `!ioauth` with encrypted data. Fields are **space-separated**:

```
!ioauth utxo1 utxo2 ... auth_pub cj_addr change_addr btc_sig
```

The `btc_sig` proves UTXO ownership by signing the maker's NaCl pubkey with a Bitcoin key.

### Phase 4: Transaction Signing (Encrypted)

Taker builds transaction, sends `!tx` with base64-encoded unsigned tx. Maker verifies transaction safety (see Maker Transaction Verification), then sends `!sig` messages (one per input) with base64-encoded witness signatures.

### Phase 5: Broadcast

Taker assembles final transaction with all signatures and broadcasts based on policy:

| Policy | Behavior | Fallback |
|--------|----------|----------|
| `self` | Always taker's node | N/A |
| `random-peer` (default) | Random (makers + taker) | Falls back to self if maker fails |
| `not-self` | Random maker only | No fallback (manual broadcast needed) |

**Broadcast Request**: `!push <base64_tx>` (not encrypted, sent via PRIVMSG)

**Maker handling**: Broadcasts "unquestioningly" since they already signed. Rate limiting prevents spam abuse.

**Maker transaction ID awareness**: By default (`random-peer` policy), only one randomly selected maker receives the `!push` request and therefore knows the final txid immediately. Other participating makers do not receive the full transaction and cannot compute the txid at that moment.

This is intentional for privacy - it reduces the number of parties who can correlate signing events with broadcast events. Makers without the txid will:
1. Create a pending history entry with the CoinJoin destination address but no txid
2. The address is permanently blacklisted from reuse (critical for privacy)
3. After wallet rescan (on restart or periodic check), they discover the txid by finding a UTXO at the destination address
4. The history entry is updated with the discovered txid and confirmation status

See "Maker Transaction ID Discovery" under Transaction History Tracking for implementation details.

**Verification**: Taker monitors network to confirm transaction appeared. For Neutrino backends, uses address-based UTXO lookup. If maker broadcast fails within timeout, fallback policy applies.

Implementation: `taker/src/taker/taker.py`, `maker/src/maker/coinjoin.py`

### Direct Peer-to-Peer Connections

After discovering makers through directory servers, takers opportunistically establish direct Tor connections to makers. This provides:

- **Privacy**: Directory servers cannot observe which takers communicate with which makers
- **Reliability**: Communication continues even if directory servers become unavailable
- **Performance**: Lower latency for time-sensitive protocol messages

**Connection Flow**:

1. **Discovery**: Taker fetches orderbook from directory servers and learns makers' onion addresses from the peerlist
2. **Direct Connection**: Taker attempts to establish a direct Tor connection to each selected maker's onion hidden service
3. **Fallback**: If direct connection fails or isn't established yet, messages are relayed through directory servers
4. **Message Routing**: Once established, all subsequent messages for that CoinJoin session use the direct connection

**Channel Consistency Enforcement**:

Critical security requirement: ALL messages within a single CoinJoin session MUST use the same communication channel (either direct or directory relay).

**Why this matters**:
- Prevents session confusion attacks where an attacker might try to inject messages via a different channel
- Ensures message ordering and prevents race conditions
- Protects against potential man-in-the-middle scenarios

**Implementation**:

Both taker and maker enforce channel consistency:

**Taker** (`taker/src/taker/taker.py`):
- `MakerSession.comm_channel`: Records the channel used for the first message (`!fill`)
- All subsequent messages (`!auth`, `!tx`, `!push`) use `force_channel` parameter to ensure same channel
- Connection priority: Direct connection preferred, falls back to directory relay

**Maker** (`maker/src/maker/coinjoin.py`):
- `CoinJoinSession.comm_channel`: Records channel from first message
- `validate_channel()`: Validates that each message arrives on the same channel
- Rejects messages that violate channel consistency with clear warning logs

**Channel Identifiers**:
- `"direct"`: Peer-to-peer onion connection
- `"dir:<host>:<port>"`: Relayed through specific directory server

**Logging**: Channel violations are logged with WARNING level showing both the expected and actual channels for debugging.

Implementation: `taker/src/taker/taker.py`, `maker/src/maker/bot.py`, `maker/src/maker/coinjoin.py`

---

## Transaction Policies

### Dust Threshold

JoinMarket enforces a configurable dust threshold to ensure transaction outputs remain economically spendable and to account for fee estimation uncertainties in collaborative CoinJoin transactions.

#### Threshold Values

Following the reference implementation's approach, we define three threshold levels:

1. **Standard Bitcoin Dust Limit**: 546 satoshis
   - Minimum output value enforced by Bitcoin Core's `IsDust()` function for P2PKH outputs
   - Calculated as: `3 * minRelayTxFee * outputSize`

2. **Bitcoin Dust Threshold**: 2,730 satoshis (5x standard limit)
   - Defined in `jmcore.constants.BITCOIN_DUST_THRESHOLD`
   - Conservative buffer for direct Bitcoin payments

3. **JoinMarket Dust Threshold**: 27,300 satoshis (10x Bitcoin threshold)
   - Defined in `jmcore.constants.DUST_THRESHOLD`
   - **Default for CoinJoin operations**
   - Provides safety margin for:
     - Fee estimation uncertainties in multi-party transactions
     - Ensuring outputs remain economically spendable under varying fee conditions
     - Preventing rejection by peers due to changing network conditions

#### Why 27,300 Satoshis?

The higher threshold for CoinJoin operations is a **JoinMarket policy**, not a Bitcoin protocol rule. It exists because:

1. **Fee Estimation Safety**: CoinJoin transactions involve multiple participants. If an output is too close to the dust limit, slight variations in fee rates during the negotiation process could make the output uneconomical to spend later.

2. **Economic Spendability**: An output must be worth more than the transaction fee needed to spend it. With rising fee rates, a 546-sat output might cost more to spend than it's worth.

3. **Network Reliability**: Nodes may reject or deprioritize transactions with outputs close to the dust limit, especially during high-fee periods.

#### Configuration

Both Maker and Taker can configure their dust threshold:

```python
# Taker configuration (taker/src/taker/config.py)
class TakerConfig(BaseModel):
    dust_threshold: int = Field(
        default=DUST_THRESHOLD,  # 27300 sats
        ge=0,
        description="Dust threshold in satoshis for change outputs"
    )

# Maker configuration (maker/src/maker/config.py)
class MakerConfig(BaseModel):
    dust_threshold: int = Field(
        default=DUST_THRESHOLD,  # 27300 sats
        ge=0,
        description="Dust threshold in satoshis for change outputs"
    )
```

#### Enforcement

The dust threshold is enforced during transaction building:

1. **Change Output Creation** (`taker/src/taker/tx_builder.py`):
   - Taker change is only created if `change_amount > dust_threshold`
   - Maker change is only created if `change_amount > dust_threshold`
   - Change below threshold is donated to miners as fee

2. **Offer Calculation** (`maker/src/maker/offers.py`):
   - Makers reserve `max(dust_threshold, tx_fee_contribution)` when calculating available liquidity
   - Ensures sufficient balance for change output or threshold buffer

#### Backward Compatibility

The configurable dust threshold maintains backward compatibility with the reference implementation:

- **Default behavior**: Uses 27,300 sats (matches reference implementation)
- **Configurable**: Can be lowered to 2,730 or 546 sats for non-CoinJoin direct payments
- **Enforced**: Always applied during transaction building to prevent accidental dust creation

#### Implementation Reference

```python
# Constants defined in jmcore/src/jmcore/constants.py
STANDARD_DUST_LIMIT = 546         # Bitcoin Core default
BITCOIN_DUST_THRESHOLD = 2730     # 5x standard (direct payments)
DUST_THRESHOLD = 27300            # 10x Bitcoin threshold (CoinJoin default)

# Transaction building with dust threshold
tx_bytes, metadata = build_coinjoin_tx(
    taker_utxos=...,
    maker_data=...,
    cj_amount=...,
    dust_threshold=config.dust_threshold,  # Configurable
    ...
)
```

#### Testing

Comprehensive tests verify dust threshold enforcement:
- `taker/tests/test_tx_builder.py::test_build_coinjoin_configurable_dust_threshold`
- Tests with 546, 27300, and custom thresholds
- Verifies change output inclusion/exclusion based on threshold

### Minimum Relay Fee

Bitcoin Core enforces a minimum relay fee (`minrelaytxfee`) that determines the lowest fee rate accepted into the node's mempool. Transactions with fee rates below this threshold are rejected with error `-26: min relay fee not met`.

#### Default Values

| Bitcoin Core Version | Default minrelaytxfee |
|---------------------|----------------------|
| v0.20.0 and later   | 0.00001 BTC/kB (1.0 sat/vB) |
| Earlier versions    | 0.00001 BTC/kB (1.0 sat/vB) |

#### Sub-satoshi Fee Rates

JoinMarket NG supports sub-satoshi fee rates (e.g., 0.5 sat/vB) for cost savings during low-fee periods. However, this requires configuring your Bitcoin node to accept lower fee rates.

To enable sub-satoshi fee rates, add to your `bitcoin.conf`:

```ini
# Minimum relay fee in BTC/kB
# 0.1 sat/vB = 0.0000001 BTC/kB
minrelaytxfee=0.0000001
```

Then restart your Bitcoin node for changes to take effect.

#### Fee Rate Resolution

Both the wallet CLI and taker automatically check the node's mempool minimum fee:

1. If a manual `--fee-rate` is below the node's minimum, a warning is logged and the mempool minimum is used instead
2. If fee estimation returns a value below the mempool minimum, the mempool minimum is used
3. This prevents broadcast failures due to "min relay fee not met" errors

#### Troubleshooting

If you see `RPC error -26: min relay fee not met`:

1. Check your node's current minimum fee: `bitcoin-cli getmempoolinfo` (look at `mempoolminfee`)
2. Either use a higher `--fee-rate`, or configure `minrelaytxfee` in `bitcoin.conf`
3. Restart bitcoind after changing `bitcoin.conf`

Note: In CoinJoin transactions, if your fee rate is below your node's minimum but above other participants' minimums, the transaction may be broadcast by another participant but rejected by your node's mempool. This can cause the transaction to appear untracked until it confirms in a block.

---

## Bitcoin Amount Handling

All bitcoin amounts are represented internally as **integer satoshis** to prevent floating-point errors.

- **Storage/Calc**: `int` satoshis (e.g., `50_000_000`).
- **External Inputs**: Convert to `int` immediately.
- **Display**: Convert to BTC string only for UI.
- **Constants**: Use `SATS_PER_BTC = 100_000_000`.

**Do not use `float` or `Decimal` for financial calculations.**

---

## PoDLE (Proof of Discrete Log Equivalence)

PoDLE prevents Sybil attacks by requiring takers to commit to UTXO ownership before makers reveal their UTXOs.

### Purpose

Without PoDLE, an attacker could request CoinJoins from many makers, collect their UTXO sets, then abort—linking maker UTXOs without cost.

### Protocol Flow

1. **Taker commits**: `C = H(P2)` where `P2 = k*J` (J is NUMS point)
2. **Maker accepts**: Sends encryption pubkey
3. **Taker reveals**: Sends `P` (pubkey), `P2`, and Schnorr-like proof
4. **Maker verifies**: `H(P2) == C`, proof valid, UTXO exists
5. **Maker broadcasts**: `!hp2` to blacklist commitment network-wide

The proof shows that `P = k*G` and `P2 = k*J` use the same private key `k` without revealing `k`.

#### Commitment Format

First byte is commitment type:
- `P`: PoDLE (default and currently only supported type)
- Others reserved for future commitment types

Full commitment format: `<type_byte><H(P2)>`

Example: `P` + 32-byte hash = 33 bytes total

### NUMS Point Index System

NUMS points provide reusability. Each UTXO can generate 10 different commitments (indices 0-9).

**Why different indices matter**: `J(0) ≠ J(1)`, so `P2_0 = k*J(0) ≠ k*J(1) = P2_1`, producing different commitments.

**Index policy**:
- Index 0: First use (preferred)
- Index 1-2: Retry after failed CoinJoins (accepted by default)
- Index 3+: Only accepted if maker configures higher `taker_utxo_retries`

After 3 failed CoinJoins with indices 0-2, taker must use a different UTXO.

### UTXO Selection for PoDLE

Not all UTXOs qualify:

| Criterion | Default | Rationale |
|-----------|---------|-----------|
| Min confirmations | 5 | Prevents double-spend |
| Min value | 20% of cj_amount | Economic stake |

Selection priority: confirmations (desc) → value (desc)

### Commitment Tracking

**Taker** (`cmtdata/commitments.json`):
- Tracks locally used commitments to avoid reuse
- Prevents linkage even if CoinJoin fails before `!auth`

**Maker** (`cmtdata/commitmentlist`):
- Network-wide blacklist received via `!hp2` broadcasts
- One commitment hash per line (ASCII)

### Blacklisting Protocol (`!hp2`)

After successful `!auth` verification:
1. Maker broadcasts `!hp2 <commitment_hex>` publicly
2. All makers add to local blacklist
3. Source obfuscation: Can relay via random peer first (PRIVMSG → PUBMSG)

Implementation: `jmcore/src/jmcore/podle.py`

---

## Fidelity Bonds

Fidelity bonds allow makers to prove locked bitcoins, improving trust and selection probability.

### Purpose

Makers lock bitcoin in timelocked UTXOs to gain priority in taker selection. Bond value increases with amount and time until unlock.

### Bond Address Generation

Fidelity bonds use P2WSH (Pay-to-Witness-Script-Hash) addresses with a timelock script:

```
<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
```

**Generate a bond address:**

```bash
jm-wallet generate-bond-address \
  --mnemonic-file wallet.enc \
  --password "your-password" \
  --locktime-date "2026-01-01" \
  --index 0 \
  --network mainnet
```

Output includes:
- **Address**: The P2WSH address to fund
- **Witness Script**: Hex and disassembled form (for recovery/verification)
- **Registry**: Bond is automatically saved to `~/.joinmarket-ng/fidelity_bonds.json`

### Bond Registry

The bond registry (`fidelity_bonds.json`) persistently stores bond metadata:

```
~/.joinmarket-ng/
└── fidelity_bonds.json    # Bond addresses, locktimes, witness scripts, UTXO info
```

**Registry Commands:**

| Command | Description |
|---------|-------------|
| `jm-wallet registry-list` | List all bonds with status (funded/unfunded/expired) |
| `jm-wallet registry-show <address>` | Show detailed bond information |
| `jm-wallet registry-sync` | Scan blockchain to update funding status |

**Example workflow:**

```bash
# Generate a bond address (automatically saved to registry)
jm-wallet generate-bond-address -f wallet.enc -p "pass" -d "2026-01-01"

# Fund the address using your preferred method (Sparrow, Bitcoin Core, etc.)

# Sync registry with blockchain to detect funding
jm-wallet registry-sync -f wallet.enc -p "pass" --rpc-url http://localhost:8332

# List all bonds and their status
jm-wallet registry-list

# Show details for a specific bond
jm-wallet registry-show bc1q...
```

**Registry fields:**
- `address`: P2WSH bond address
- `locktime`: Unix timestamp when funds can be spent
- `witness_script_hex`: The redeem script (needed for spending)
- `txid`, `vout`, `value`: UTXO info (populated after `registry-sync`)
- `is_funded`: Whether the bond has a confirmed UTXO
- `is_expired`: Whether the locktime has passed

### Descriptor Wallet Lifecycle

**Important:** The `descriptor_wallet` backend requires importing bond addresses into Bitcoin Core's wallet before they can be detected on-chain.

#### Bond Creation Flow

When you create a new bond with `generate-bond-address`:
1. ✅ Bond metadata is saved to `fidelity_bonds.json`
2. ❌ Address is **NOT** imported to descriptor wallet yet

#### Bond Discovery Flow

When you discover bonds with `recover-bonds`:
1. ✅ Scans blockchain for bonds at all timelocks
2. ✅ Saves found bonds to `fidelity_bonds.json`
3. ✅ **Automatically imports** discovered addresses to descriptor wallet (for descriptor_wallet backend)

#### Bond Syncing Flow

When you sync with `registry-sync`:
1. ✅ Reads bonds from `fidelity_bonds.json`
2. ✅ **Automatically imports** bond addresses if using descriptor_wallet backend
3. ✅ Updates UTXO info (txid, vout, value, confirmations)

#### Maker Bot Startup

When the maker bot starts:
1. ✅ Loads bonds from `fidelity_bonds.json`
2. ✅ **Automatically imports** bond addresses during wallet setup
3. ✅ Detects funded bonds and includes proof in offers

#### Manual Operations (info/send)

When using `jm-wallet info` or `jm-wallet send`:
1. ✅ Loads bonds from `fidelity_bonds.json`
2. ✅ **Automatically imports** bond addresses if wallet exists
3. ✅ Shows bond UTXOs in balance/transaction

**Key Point:** All commands now handle descriptor import automatically. You don't need to manually import bond addresses.

### Spending Fidelity Bonds

After the locktime expires, bonds can be spent using the `send` command:

```bash
jm-wallet send <destination> \
  --mnemonic-file wallet.enc \
  --password "your-password" \
  --mixdepth 0 \
  --amount 0  # Sweep all
```

The wallet automatically:
1. Detects P2WSH (timelocked) UTXOs
2. Sets `nLockTime` to the bond's locktime
3. Creates the proper witness stack with the witness script
4. Blocks spending attempts before locktime expires

**Important**: P2WSH fidelity bond UTXOs cannot be used in CoinJoins. The maker and taker will reject them with an error to protect your funds.

### Bond Proof Structure

The fidelity bond proof is a 252-byte binary blob containing two signatures + metadata:

#### Binary Blob Structure (252 bytes total)

| Field | Size | Description |
|-------|------|-------------|
| nick_sig | 72 | DER signature (padded with 0xff) |
| cert_sig | 72 | DER signature (padded with 0xff) |
| cert_pubkey | 33 | Certificate public key |
| cert_expiry | 2 | Retarget period number when cert becomes invalid (unsigned int, little-endian) |
| utxo_pubkey | 33 | UTXO public key |
| txid | 32 | Transaction ID |
| vout | 4 | Output index (little-endian) |
| timelock | 4 | Locktime value (little-endian) |

**DER signature padding**: Padded at start with 0xff bytes to exactly 72 bytes. The header byte 0x30 makes stripping padding straightforward during verification.

**Signature purposes**:
- **Nick signature** (72 bytes): Proves maker controls certificate key (signs `taker_nick|maker_nick`)
- **Certificate signature** (72 bytes): Self-signs certificate binding cert key to UTXO (signs `fidelity-bond-cert|cert_pub|expiry`)
- **Certificate pubkey** (33 bytes): Hot wallet key
- **UTXO pubkey** (33 bytes): Cold storage key (can equal cert_pub for self-signed)
- **UTXO identifiers** (txid, vout, timelock): On-chain bond location

#### Certificate Expiry Format

The certificate expiry field (2 bytes) is stored as a retarget period number that determines when the certificate becomes invalid:

- **Encoding**: 2-byte unsigned integer (little-endian)
- **Represents**: Difficulty retarget period number (period = block_height / 2016)
- **Calculation**: `cert_expiry = ((current_block + 2) // 2016) + 1`
  - `current_block`: Current blockchain height when proof is created
  - `+2`: Safety margin to reduce chances of proof expiring before verification
  - `+1`: Validity time (1 retarget period ≈ 2 weeks)
- **Validation**: Certificate is invalid if `current_block_height > cert_expiry × 2016`
- **Example**: At block 930,471: cert_expiry = ((930471 + 2) / 2016) + 1 = 462
  - Certificate becomes invalid after block 931,392 (462 × 2016)
  - Time window: ~2 weeks from proof creation

### Verification

Takers verify:
1. Nick signature using cert_pub (proves maker identity)
2. Certificate signature using utxo_pub (proves UTXO ownership)
3. UTXO exists on-chain with correct locktime
4. Bond value calculation from amount + time-to-unlock

### Certificate Chain

```
UTXO keypair (cold) → signs → certificate (hot) → signs → nick proofs (per-taker)
```

Allows cold storage of bond privkey while hot wallet handles per-session proofs.

### Cold Wallet Setup (External Wallet / Hardware Wallet)

For maximum security, fidelity bonds can use a certificate chain that keeps the bond UTXO private key completely offline in cold storage (hardware wallet). The bond private key never touches any internet-connected device.

**Workflow:**

1. **Get public key from hardware wallet** (using Sparrow Wallet):
   - Open Sparrow Wallet and connect your hardware wallet
   - Navigate to the Addresses tab
   - Find or create an address at the fidelity bond derivation path: `m/84'/0'/0'/2/0`
   - Right-click the address and select "Copy Public Key"
   - Save this public key (33-byte compressed format, starts with 02 or 03)

2. **Create bond address from public key** (on online machine - NO private keys needed):
   ```bash
   jm-wallet create-bond-address <pubkey_from_step_1> \
     --locktime-date "2026-01" \
     --network mainnet
   ```
   This creates the bond address WITHOUT requiring your mnemonic. Note the address.

3. **Fund the bond address**: Send Bitcoin to the address from step 2.

4. **Generate hot wallet keypair** (on online machine):
   ```bash
   jm-wallet generate-hot-keypair
   ```
   This creates a random keypair. Store both the private and public keys securely.

5. **Prepare certificate message** (on online machine - NO private keys needed):
   ```bash
   jm-wallet prepare-certificate-message <bond_address> \
     --cert-pubkey <hot_wallet_pubkey> \
     --cert-expiry-blocks 104832  # ~2 years
   ```
   This outputs the message that needs to be signed.

6. **Sign the message** (using hardware wallet with Sparrow or similar):
   - Open Sparrow Wallet and connect your hardware wallet
   - Go to Tools -> Sign/Verify Message
   - Select the address that matches your bond's public key
   - Paste the hex message from step 5
   - Sign with your hardware wallet
   - Copy the resulting signature

7. **Import certificate** (on online machine):
   ```bash
   jm-wallet import-certificate <bond_address> \
     --cert-pubkey <hot_wallet_pubkey> \
     --cert-privkey <hot_wallet_privkey> \
     --cert-signature <signature_from_hardware_wallet> \
     --cert-expiry 52  # Periods (104832 blocks / 2016)
   ```
   This imports the certificate into the bond registry.

8. **Run maker**: The maker will automatically detect certificates and use them.
   ```bash
   jm-maker start --mnemonic-file hot-wallet.enc
   ```

**Security benefits:**
- Bond UTXO private key NEVER leaves the hardware wallet
- No mnemonic exposure to online systems
- Certificate expires after configurable period (~2 years default)
- If hot wallet is compromised, attacker can only impersonate bond until expiry
- Bond funds remain safe in cold storage

**Certificate expiry:** Specified in 2016-block periods (Bitcoin difficulty adjustment period). Example: `cert_expiry=52` means 52 x 2016 = 104,832 blocks (approximately 2 years). After expiry, sign a new certificate message to continue using the bond.

### Protocol: Bond Announcement

Fidelity bonds are only sent via PRIVMSG as a direct response to `!orderbook` requests. They are not included in the initial PUBLIC offer announcements. The reference orderbook watcher only requests offers once on startup, so any offer posted afterwards does not show a bond. This does not affect takers who will always receive bond proofs when they request the orderbook.

The Nick Signature binds the bond proof to the specific taker, preventing replay attacks.
---

## Tor Integration

All JoinMarket components use Tor for privacy in different ways:

| Component | SOCKS Proxy | Hidden Service | Notes |
|-----------|-------------|----------------|-------|
| **Directory Server** | No | Permanent | Receives connections only; stable `.onion` for configs |
| **Maker** | Yes | Ephemeral (recommended) | Outgoing + incoming; fresh identity per session |
| **Taker** | Yes | No | Outgoing only; advertises `NOT-SERVING-ONION` |
| **Orderbook Watcher** | Yes | No | Monitoring only |

### Directory Server

Tor-agnostic—only receives connections. Requires permanent hidden service in `torrc`:

```
HiddenServiceDir /var/lib/tor/directory_hs
HiddenServiceVersion 3
HiddenServicePort 5222 directory_server:5222
```

### Maker

**SOCKS proxy** for outgoing connections to directories:

```bash
jm-maker start --socks-host=127.0.0.1 --socks-port=9050
```

**Ephemeral hidden service** (recommended) via Tor control port:

```
# torrc
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
```

```bash
jm-maker start \
  --tor-control-enabled \
  --tor-control-host=127.0.0.1 \
  --tor-control-port=9051 \
  --tor-cookie-path=/var/lib/tor/control_auth_cookie
```

Creates fresh `.onion` each session for better privacy. Fidelity bond value is calculated from on-chain data (amount/locktime), not identity, so ephemeral addresses don't affect trustworthiness.

### Taker / Orderbook Watcher

Only need SOCKS proxy for outgoing connections:

```bash
jm-taker coinjoin --socks-host=127.0.0.1 --socks-port=9050 ...
```

Implementation: `jmcore/src/jmcore/tor_control.py`

### Multi-Channel Message Deduplication

When connected to N directory servers, each message is received N times (once per server). The deduplication system prevents:
1. Processing the same protocol message multiple times (expensive operations like `!auth`, `!tx`)
2. Rate limiter counting duplicates as violations
3. Log spam from duplicate messages

**Message Fingerprinting**: Messages are identified by `from_nick:command:first_arg`:
- `alice:fill:order123` - Fill request for order 123
- `bob:pubkey:abc123` - Pubkey response

**Time-Based Window**: Duplicates within a 30-second window are dropped. Window should exceed expected network latency variance between directory servers.

**Implementation**:
- **Maker** (`maker/bot.py`): Uses `MessageDeduplicator` from `jmcore.deduplication` to filter incoming messages before processing
- **Taker** (`taker/taker.py`): Uses `ResponseDeduplicator` in `MultiDirectoryClient.wait_for_responses()` to collect unique responses

**Orderbook Deduplication**: The taker's orderbook uses `(counterparty, oid)` as the key for offer deduplication, matching the reference implementation's approach.

**Statistics**: Both deduplicators track stats (total processed, duplicates dropped, duplicate rate) for debugging multi-directory configurations.

---

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

### Running Tests

To run all unit tests with coverage:

```bash
pytest -lv \
  --cov=jmcore \
  --cov=jmwallet \
  --cov=directory_server \
  --cov=orderbook_watcher \
  --cov=maker \
  --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests
```

For E2E tests, see the [E2E README](./tests/e2e/README.md).

---

## Troubleshooting

### Wallet Sync Issues

If wallet sync hangs or times out, use these `bitcoin-cli` commands to debug:

```bash
# List loaded wallets (jm-wallet creates descriptive names like jm_<hash>_<network>)
bitcoin-cli listwallets

# Replace <wallet_name> with your wallet name from listwallets
WALLET="jm_xxxxxxxx_mainnet"

# Check wallet balance
bitcoin-cli -rpcwallet="$WALLET" getbalance

# List unspent outputs (UTXOs)
bitcoin-cli -rpcwallet="$WALLET" listunspent

# List addresses that received funds (useful for fidelity bonds)
bitcoin-cli -rpcwallet="$WALLET" listreceivedbyaddress

# Manually trigger blockchain rescan from a specific height
# Use height 0 for full rescan, or a recent height for faster sync
bitcoin-cli -rpcwallet="$WALLET" rescanblockchain 900000

# Check rescan progress
bitcoin-cli -rpcwallet="$WALLET" getwalletinfo
```

**Common Sync Issues**:

| Symptom | Cause | Solution |
|---------|-------|----------|
| First sync times out | Initial descriptor import triggers full scan | Wait and retry - background scan continues |
| Second sync hangs | Concurrent rescan still running | Check `getwalletinfo` for scan progress |
| Missing transactions | Scan started too late | Use `rescanblockchain` with earlier height |
| Wrong balance | BIP39 passphrase mismatch | Verify passphrase with `jm-wallet info` |

### Smart Scan Configuration

For faster initial sync of newer wallets, reduce the lookback period:

```toml
[wallet]
# ~3 months instead of ~1 year default
scan_lookback_blocks = 12960

# Or set explicit start height
scan_start_height = 870000
```

The smart scan performs a quick scan of recent blocks first, then triggers a full background rescan to ensure no transactions are missed. You can monitor the background scan with `bitcoin-cli getwalletinfo`.

### RPC Timeout Issues

If you see RPC timeout errors during wallet operations:

1. Check Bitcoin Core is fully synced: `bitcoin-cli getblockchaininfo`
2. Increase RPC timeout in Bitcoin Core config: `rpcservertimeout=120`
3. For large wallets, the first scan may take several minutes - retry after it completes

---

## Security Model

### Threat Model

- **Attackers**: Malicious peers, network observers, malicious directory operators
- **Assets**: Peer privacy, network availability, user funds
- **Threats**: DDoS, privacy leaks, message tampering, eclipse attacks

### Defenses

1. **Privacy**: Tor-only connections
2. **Rate Limiting**: Per-peer message limits (token bucket, configurable via `message_rate_limit`)
3. **Validation**: Protocol enforcement, input validation
4. **Network Segregation**: Mainnet/testnet isolation
5. **Authentication**: Handshake protocol, feature-based capability detection

### Directory Server Threat Model

Directory servers are similar to Bitcoin DNS seed nodes - they are only required for **peer discovery**, not message routing (which can happen directly via onion addresses). However, they still represent security-relevant infrastructure:

#### Threats

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **Eclipse Attack** | Malicious directory feeds poisoned peer list, isolating victim | Multi-directory fallback, peer diversity heuristics |
| **Selective Censorship** | Directory blocks specific nicks/addresses | Ephemeral nicks per session, multiple directories |
| **Metadata Correlation** | Timing + nick/IP linkage at directory | Tor connections, ephemeral nicks derived from session keys |
| **DoS** | Flood directory with connections/messages | Rate limiting, connection limits, message size limits |

#### Multi-Directory Strategy

For production deployments, takers and makers should:
1. Connect to multiple independent directory servers
2. Merge and deduplicate peer lists
3. Prefer direct P2P connections (via onion addresses) over directory-relayed messages
4. Rotate directory connections periodically

### Message Security

#### Rate Limiting

The directory server enforces per-peer rate limits using a token bucket algorithm:

| Setting | Default | Description |
|---------|---------|-------------|
| `message_rate_limit` | 100/s | Sustained message rate |
| `message_burst_limit` | 200 | Maximum burst size |
| `rate_limit_disconnect_threshold` | 50 | Violations before disconnect |
| `max_message_size` | 2MB | Maximum message size |
| `max_line_length` | 64KB | Maximum JSON-line message length |
| `max_json_nesting_depth` | 10 | Maximum JSON nesting depth |

#### JSON-Line Message Parsing Limits

To prevent DoS attacks through malformed messages, the protocol enforces strict parsing limits:

1. **Line Length Validation**: Checked **before** JSON parsing to prevent memory exhaustion
   - Messages exceeding `max_line_length` (64KB default) are rejected immediately
   - Prevents attackers from sending multi-megabyte JSON payloads

2. **Nesting Depth Validation**: Enforced **after** parsing but before model creation
   - JSON structures deeper than `max_json_nesting_depth` (10 levels default) are rejected
   - Prevents stack overflow attacks via deeply nested objects/arrays

3. **Pre-Parse Validation Flow**:
   ```
   Raw Message → Line Length Check → JSON Parse → Nesting Depth Check → Model Creation
   ```

These limits are applied in `MessageEnvelope.from_bytes()` and configured per directory server instance.

#### Protocol Commands

| Command | Encrypted | Notes |
|---------|-----------|-------|
| `!pubkey` | No | Initial key exchange |
| `!fill`, `!auth`, `!ioauth`, `!tx`, `!sig` | Yes (NaCl) | CoinJoin negotiation |
| `!push` | No | Transaction broadcast (intentional for privacy) |
| `!sw0reloffer` | No | Public orderbook |

Note: `!push` is intentionally unencrypted because the transaction is already public broadcast data. The privacy benefit is that the taker's IP is not linked to the broadcast.

#### Channel Consistency

To prevent session confusion and potential attacks, both takers and makers enforce strict channel consistency within each CoinJoin session:

**Security Requirement**: All messages in a CoinJoin session MUST use the same communication channel (either direct P2P or directory relay).

**Attack Scenarios Prevented**:

1. **Session Confusion**: Attacker intercepts messages on one channel and re-sends them on another, attempting to confuse the session state
2. **Message Injection**: Malicious directory operator or network observer tries to inject messages via a different channel mid-session
3. **Race Conditions**: Messages arriving simultaneously on different channels could cause state machine inconsistencies

**Enforcement**:

- **First Message**: The channel used for `!fill` (taker→maker) establishes the session channel
- **Validation**: Each subsequent message (`!auth`, `!tx`, `!push`) is validated against the recorded channel
- **Rejection**: Messages violating channel consistency are rejected with WARNING logs
- **No Fallback**: Once a channel is established, the session will NOT fall back to a different channel

**Channel Identifiers**:
- Direct: `"direct"`
- Directory: `"dir:<host>:<port>"`

**Logging Example**:
```
WARNING | Channel consistency violation for J5taker123:
         session started on 'dir:node1.example.com:6667',
         received message on 'direct'
```

This ensures that if a taker establishes a direct connection after sending `!fill` via directory, the maker will reject subsequent messages from the direct connection, forcing the taker to continue using the directory relay for that specific session.

### Neutrino/Light Client Security

When using the Neutrino backend (BIP157/BIP158), additional protections prevent DoS attacks:

| Protection | Default | Description |
|------------|---------|-------------|
| `max_watched_addresses` | 10,000 | Prevents memory exhaustion |
| `max_rescan_depth` | 100,000 blocks | Limits expensive rescans |
| Blockheight validation | SegWit activation | Rejects suspiciously old heights |

**Neutrino Server Privacy**: If pointing to a third-party neutrino-api server, that server can observe timing, addresses, and query patterns. **Recommendation**: Run neutrino-api locally behind Tor, or use the bundled Docker deployment.

### Attack Mitigations

- **DDoS**: Connection limits, rate limiting, message size limits
- **Sybil**: Fidelity bonds (maker verification), resource limits
- **Replay**: Session-bound state machines, ephemeral keys
- **MitM**: End-to-end NaCl encryption (JM protocol)
- **Rescan Abuse**: Blockheight validation, depth limits

### Critical Security Code

The following modules are security-critical and have been designed to prevent loss of funds:

| Module | Purpose | Test Coverage |
|--------|---------|---------------|
| `maker/tx_verification.py` | Verifies CoinJoin transactions before signing | 100% |
| `jmwallet/wallet/signing.py` | Transaction signing | 95% |
| `jmcore/podle.py` | Anti-sybil proof verification | 90%+ |
| `directory_server/rate_limiter.py` | DoS prevention | 100% |
| `jmwallet/backends/neutrino.py` | Light client UTXO verification | 80%+ |

### Maker Transaction Verification Checklist

The `verify_unsigned_transaction()` function in `maker/tx_verification.py` performs these critical checks before signing:

1. **Input Inclusion**: All maker UTXOs are present in transaction inputs
2. **CoinJoin Output**: Exactly one output pays `>= amount` to maker's CJ address
3. **Change Output**: Exactly one output pays `>= expected_change` to maker's change address
4. **Positive Profit**: `cjfee - txfee > 0` (maker never pays to participate)
5. **No Duplicate Outputs**: CJ and change addresses appear exactly once each
6. **Well-formed Transaction**: Parseable, valid structure

If any check fails, the maker refuses to sign and logs the specific failure reason.

---

## Reproducible Builds

JoinMarket NG supports reproducible Docker builds, allowing anyone to verify that released images were built from the published source code. This is critical for security-sensitive software handling Bitcoin transactions.

### Why Reproducible Builds Matter

Reproducible builds provide assurance that:
- Binary releases match the source code (no backdoors injected during CI)
- Multiple parties can independently verify the same build produces identical results
- Users don't need to trust the build infrastructure or release maintainers

For Bitcoin privacy software like JoinMarket, this is especially important as compromised builds could:
- Leak private keys or transaction data
- Introduce subtle privacy degradation
- Create transactions that lose funds

### How It Works

Our reproducible builds use several techniques:

1. **SOURCE_DATE_EPOCH**: All timestamps in Docker images use the git commit timestamp, not build time
2. **Pinned dependencies**: `requirements.txt` files lock exact package versions
3. **Deterministic ordering**: Package installations are sorted alphabetically
4. **BuildKit reproducibility**: Uses Docker BuildKit features for consistent layer hashes

### Building Locally

To reproduce a release build locally:

```bash
# Get the release info
VERSION=1.0.0
git checkout $VERSION
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

# Build with the same timestamp
docker buildx build \
  --file ./maker/Dockerfile \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --output type=docker \
  .
```

### Verifying Releases

Each release includes a manifest file with:
- Git commit hash
- SOURCE_DATE_EPOCH used for the build
- Docker image digests (sha256)

Use the verification script to check a release:

```bash
# Basic verification (checks signatures and digests)
./scripts/verify-release.sh 1.0.0

# Full verification with local reproduction
./scripts/verify-release.sh 1.0.0 --reproduce

# Require multiple signatures
./scripts/verify-release.sh 1.0.0 --min-sigs 2
```

### Signing a Release

Trusted parties can sign releases to attest they've verified the build:

```bash
# Sign a release (optionally verify reproducibility first)
./scripts/sign-release.sh 1.0.0 --verify-first

# Use a specific GPG key
./scripts/sign-release.sh 1.0.0 --key ABCD1234...
```

After signing:
1. Your signature is saved to `signatures/<version>/<fingerprint>.sig`
2. Commit and push (or create a PR if you don't have write access)
3. Add your key to `signatures/trusted-keys.txt` to be included in automated verification

### Verifying Signatures

To verify that trusted parties have signed a release:

```bash
# Check signatures (downloads manifest, imports trusted keys, verifies)
./scripts/verify-release.sh 1.0.0
```

The script will:
1. Download the release manifest from GitHub releases
2. Import trusted keys from `signatures/trusted-keys.txt`
3. Verify all signatures in `signatures/<version>/`
4. Check Docker image digests match the manifest

### Trusted Keys

The list of trusted signers is maintained in `signatures/trusted-keys.txt`. To add your key:

1. Generate a GPG key if you don't have one: `gpg --full-generate-key`
2. Upload to a keyserver: `gpg --keyserver hkps://keys.openpgp.org --send-keys <fingerprint>`
3. Submit a PR adding your fingerprint to `signatures/trusted-keys.txt`

### CI/CD Integration

The release workflow automatically:
1. Builds images with `SOURCE_DATE_EPOCH` set to the git commit timestamp
2. Generates a release manifest with all image digests
3. Uploads the manifest to GitHub releases

Maintainers should then sign the manifest and push their signatures.

### Limitations

Perfect bit-for-bit reproducibility depends on:
- Same BuildKit version
- Same base image version (pinned in Dockerfiles)
- Same host architecture for single-arch builds

Multi-architecture builds may have slight variations due to platform-specific compilation. The verification process checks the manifest digests match the registry, not that you can reproduce the exact same bytes locally.

---

## References

- [Original JoinMarket Implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/)
- [JoinMarket Protocol Documentation](https://github.com/JoinMarket-Org/JoinMarket-Docs)
- [PoDLE Design](https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8)
- [Fidelity Bonds Design](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af)
- [BIP157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP158 - Compact Block Filters](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
- [Reproducible Builds](https://reproducible-builds.org/)
- [Docker Reproducible Builds](https://docs.docker.com/build/ci/github-actions/reproducible-builds/)
