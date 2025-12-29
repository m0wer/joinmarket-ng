# JoinMarket Protocol Documentation

This document consolidates the JoinMarket protocol specification, implementation details, architecture, and testing guide for the modern Python refactored implementation.

## Overview

JoinMarket is a decentralized CoinJoin implementation that allows Bitcoin users to improve their transaction privacy through collaborative transactions. The protocol consists of two main participant types:

- **Makers**: Liquidity providers who offer their UTXOs for CoinJoin and earn fees
- **Takers**: Users who initiate CoinJoins by selecting makers and coordinating the transaction

### Key Design Principles

1. **Trustless**: No central coordinator; the taker constructs the transaction
2. **Privacy-preserving**: End-to-end encryption for sensitive data
3. **Sybil-resistant**: PoDLE commitments prevent costless DOS attacks
4. **Decentralized**: Multiple redundant directory servers for message routing

---

## Architecture

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
└── coinjoin_history.csv   CoinJoin transaction history log
```

### Configuration

**Direct Python usage:**
- Default: `~/.joinmarket-ng`
- Override with `--data-dir` CLI flag or `$JOINMARKET_DATA_DIR` environment variable

**Docker usage:**
- Default: `/home/jm/.joinmarket` (mounted as volume)
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
- CSV format for easy analysis with external tools
- View with: `jm-wallet history --stats` or `jm-wallet history --limit 10`

---

## Dependency Management

### Overview

JoinMarket NG uses a modern, maintainable dependency management system:

- **Single source of truth**: `pyproject.toml` defines all dependencies
- **Version pinning**: `requirements.txt` files lock exact versions for reproducibility
- **Development dependencies**: `requirements-dev.txt` files for testing and tooling
- **Local packages**: Internal libraries (`jmcore`, `jmwallet`) installed via `pip install -e`

### Structure

Each package has:

```
package/
├── pyproject.toml         # Source of truth: dependencies, metadata, tooling config
├── requirements.txt       # Locked production dependencies (pip-compiled)
└── requirements-dev.txt   # Locked dev dependencies (pip-compiled)
```

### Dependency Installation Order

For packages with local dependencies, install in this order:

```bash
# 1. Install jmcore (foundation library)
cd jmcore
pip install -r requirements.txt
pip install -e .

# 2. Install jmwallet (depends on jmcore)
cd ../jmwallet
pip install -r requirements.txt
pip install -e .

# 3. Install dependent packages (maker, taker, etc.)
cd ../maker
pip install -r requirements.txt
pip install -e .
```

For development:

```bash
# After installing production dependencies
pip install -r requirements-dev.txt
```

### Updating Dependencies

#### Update a Single Package Dependency

1. Edit `pyproject.toml` with new version
2. Recompile locked dependencies using the update script or manual compilation:

#### Update All Dependencies

Use the helper script:

```bash
./scripts/update-deps.sh
```

This script:
1. Compiles `requirements.txt` from `pyproject.toml` for all packages
2. Safely handles local package references (`jmcore`, `jmwallet`) by stripping them during compilation (since they are not on PyPI)
3. Compiles `requirements-dev.txt` for development dependencies

#### Manual Update (Advanced)

If you need to update manually, you must strip local package references from `requirements.txt` after compilation, as `pip-compile` cannot resolve local editable installs from PyPI.

```bash
# Example for maker
cd maker
pip-compile --strip-extras pyproject.toml -o requirements.txt
sed -i '/jmcore/d' requirements.txt
sed -i '/jmwallet/d' requirements.txt
```

### Docker Builds

Dockerfiles install dependencies in layers:

```dockerfile
# 1. Install jmcore deps and source
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install -r /app/jmcore/requirements.txt
COPY jmcore/src /app/jmcore/src
COPY jmcore/pyproject.toml /app/jmcore/
RUN pip install -e /app/jmcore

# 2. Install package deps (already constrained by jmcore)
COPY package/requirements.txt /app/package/requirements.txt
RUN pip install -r /app/package/requirements.txt

# 3. Install package source
COPY package/src /app/package/src
COPY package/pyproject.toml /app/package/
RUN pip install -e /app/package
```

### Why This Approach?

**Problem**: Can't use `pip-compile` with local package references like `jmcore` easily because they're not on PyPI.

**Solution**:
1. Define all dependencies in `pyproject.toml` (single source of truth)
2. Use a script to compile `requirements.txt` while temporarily stripping local package refs
3. Install local packages explicitly in CI/Docker

**Benefits**:
- ✅ Single source of truth in `pyproject.toml`
- ✅ Full version pinning for security and reproducibility
- ✅ Clean separation of local vs. PyPI dependencies
- ✅ Works seamlessly with Docker multi-stage builds
- ✅ pip-compile compatibility
- ✅ Easy to maintain and understand

---

## Design Principles

This refactor follows SOLID principles and modern Python best practices:

### Single Responsibility Principle

Each module has one clear purpose:
- `PeerRegistry`: Manages peer state only
- `MessageRouter`: Routes messages only
- `HandshakeHandler`: Handles handshakes only
- `ConnectionManager`: Manages connections only

### Open/Closed Principle

- Extensible through interfaces and dependency injection
- `Connection` abstract base class allows different transport implementations
- `MessageRouter` accepts callback functions for extensibility

### Liskov Substitution Principle

- `TCPConnection` can substitute `Connection` without breaking code
- `OnionDirectoryPeer` can substitute `OnionPeer` in original design

### Interface Segregation Principle

- Small, focused interfaces
- Clients only depend on methods they use

### Dependency Inversion Principle

- High-level modules depend on abstractions
- `DirectoryServer` depends on `PeerRegistry` interface, not implementation
- Easy to mock for testing

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         JoinMarket System                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      Directory Server                           │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │    │
│  │  │  Connection  │  │    Peer      │  │   Message    │           │    │
│  │  │   Manager    │──│  Registry    │──│    Router    │           │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                            ▲                                            │
│                            │ connects                                   │
│         ┌──────────────────┼──────────────────┐                         │
│         │                  │                  │                         │
│         ▼                  ▼                  ▼                         │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐                  │
│  │   Maker     │   │  Orderbook   │   │   Taker      │                  │
│  │    Bot      │   │   Watcher    │   │    Bot       │                  │
│  └─────────────┘   └──────────────┘   └──────────────┘                  │
│         │                                     │                         │
│         │                                     │                         │
│         ▼                                     ▼                         │
│  ┌─────────────────────────────────────────────────┐                    │
│  │                    jmwallet                     │                    │
│  │  ┌──────────────┐  ┌──────────────┐             │                    │
│  │  │  BIP32/39/84 │  │   Backends   │             │                    │
│  │  │    Wallet    │  │ (Core, SPV)  │             │                    │
│  │  └──────────────┘  └──────────────┘             │                    │
│  └─────────────────────────────────────────────────┘                    │
│                            │                                            │
│                            │ uses                                       │
│                            ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                          jmcore                                 │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │    │
│  │  │   Protocol   │  │    Models    │  │    Crypto    │           │    │
│  │  │   Messages   │  │  (Pydantic)  │  │  Primitives  │           │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │    │
│  │  ┌──────────────┐  ┌──────────────┐                             │    │
│  │  │   Network    │  │    Bond      │                             │    │
│  │  │  Primitives  │  │    Calc      │                             │    │
│  │  └──────────────┘  └──────────────┘                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

#### Connection Establishment

```
Client                    Directory Server
  │                             │
  ├──────TCP Connect───────────▶│
  │                             │ Create Connection
  │                             │
  ├──────Handshake Msg─────────▶│
  │                             │ Validate Handshake
  │                             │ Register Peer
  │                             │
  │◀─────Handshake Response─────┤
  │                             │
  │◀─────Peer List──────────────┤
  │                             │
```

#### Message Routing

```
Sender              Directory              Receiver
  │                     │                     │
  ├─────PubMsg─────────▶│                     │
  │                     ├─────PubMsg─────────▶│
  │                     ├─────PubMsg─────────▶│ (all peers)
  │                     ├─────PubMsg─────────▶│
  │                     │                     │
  ├─────PrivMsg────────▶│                     │
  │                     ├─────PrivMsg────────▶│ (target only)
  │                     │                     │
  │                     ├─────PeerList───────▶│ (notify sender location)
  │                     │                     │
```

---

## Wallet Design

JoinMarket uses BIP32 Hierarchical Deterministic wallets with a specific structure designed to prevent address reuse and maintain privacy across CoinJoins.

### HD Structure

```
m / purpose' / coin_type' / account' / mixdepth / external_internal / index
```

Default path: `m/84'/0'/0'/mixdepth/chain/index` (Native SegWit P2WPKH)

### Mixdepths

The wallet is divided into **mixdepths** (default: 5), which function as isolated accounts:

- Inputs for a CoinJoin are always taken from a **single mixdepth**
- CoinJoin outputs go to the **next mixdepth** (wrapping from 4 → 0)
- Change outputs stay in the **same mixdepth** (internal branch)

This design ensures that CoinJoin outputs are never merged with their change, preventing trivial linkage.

### Address Branches

Each mixdepth has two branches:

- **External (0)**: For receiving payments
- **Internal (1)**: For change outputs

```
mixdepth 0
 external addresses m/84'/0'/0'/0/0/
   m/84'/0'/0'/0/0/0 bc1q... (receive)
   m/84'/0'/0'/0/0/1 bc1q... (receive)
 internal addresses m/84'/0'/0'/0/1/
   m/84'/0'/0'/0/1/0 bc1q... (change)

mixdepth 1
 external addresses m/84'/0'/0'/1/0/
   ...
```

### No BerkeleyDB Dependency

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
→ Also supports Neutrino SPV (zero full node setup!)
→ Beginner-friendly AND privacy-preserving
```

### UTXO Selection Strategies

JoinMarket NG implements sophisticated UTXO selection algorithms for both takers and makers, balancing privacy, fees, and UTXO consolidation.

#### Taker UTXO Selection

**Normal Mode (Frugal)**

By default, takers select the **minimum number of UTXOs** needed to fund the CoinJoin:

```python
# Select just enough to cover cj_amount + fees + buffer
utxos = wallet.select_utxos(mixdepth, required_amount)
```

This minimizes transaction fees and reduces fingerprinting (fewer inputs = less blockchain data).

**Sweep Mode (amount=0)**

When `amount=0`, the taker performs a **sweep** - using ALL UTXOs from the mixdepth with **zero change output**:

```bash
# Sweep all funds from mixdepth 0 to next mixdepth (internal)
jm-taker coinjoin --amount=0 --mixdepth=0 --destination=INTERNAL

# Sweep to external address
jm-taker coinjoin --amount=0 --mixdepth=0 --destination=bc1q...

# Sweep with environment variables
MNEMONIC="your seed phrase..." \
BITCOIN_RPC_URL=http://localhost:8332 \
jm-taker coinjoin -a 0 -m 0 -d INTERNAL
```

Sweep mode provides **maximum privacy**:
- No change output means no change-to-input linkage
- Exact CJ amount is calculated: `cj_amount = total_inputs - maker_fees - tx_fee`
- For relative fees, this is solved iteratively: `cj_amount = (total - tx_fee - abs_fees) / (1 + sum_rel_fees)`

**Fee Handling in Sweep Mode:**

Sweep transactions use **estimated maximum fees** when selecting makers, but actual fees may be lower:
- Initial selection uses `--max-abs-fee` and `--max-rel-fee` limits
- Final transaction uses actual maker fees (often lower than limits)
- **Residual goes to miners** as additional transaction fee (not change output)

This is intentional and beneficial:
- ✅ No dust change output that would harm privacy
- ✅ Higher miner fee improves confirmation speed
- ✅ Simplifies transaction structure (fewer outputs)

Example: If you sweep 1,000,000 sats with max fees of 5,000 sats but actual fees are 3,500 sats, the extra 1,500 sats becomes additional miner fee rather than creating a dust change output.

**Privacy Implications:**
- ✅ Best: Sweep (no change = no linkage)
- ✅ Good: Single UTXO input (simple transaction)
- ⚠️ Moderate: Multiple inputs (reveals UTXO clustering)

#### Maker UTXO Selection (Merge Algorithms)

Makers can configure their UTXO selection strategy via the `merge_algorithm` setting. Since **takers pay all transaction fees**, makers can add extra inputs at no cost to consolidate their UTXOs.

**Available Algorithms:**

| Algorithm | Behavior | Use Case |
|-----------|----------|----------|
| `default` | Minimum UTXOs needed | Minimize blockchain footprint |
| `gradual` | +1 extra UTXO beyond minimum | Slow consolidation |
| `greedy` | ALL UTXOs from mixdepth | Maximum consolidation |
| `random` | +0 to +2 extra UTXOs randomly | Obfuscate strategy |

**Configuration Example:**

```bash
# Start maker with greedy merge algorithm (consolidate all UTXOs)
jm-maker start \
  --mnemonic-file=mnemonic.txt \
  --merge-algorithm=greedy \
  --rpc-url=http://localhost:8332 \
  --rpc-user=user --rpc-password=pass

# Use environment variables
MNEMONIC="your seed phrase..." \
BITCOIN_RPC_URL=http://localhost:8332 \
BITCOIN_RPC_USER=user \
BITCOIN_RPC_PASSWORD=pass \
MERGE_ALGORITHM=gradual \
jm-maker start

# Default (minimum UTXOs) - most private
jm-maker start -f mnemonic.txt
```

Alternatively, configure programmatically:

```python
from maker.config import MakerConfig, MergeAlgorithm

config = MakerConfig(
    mnemonic="your seed phrase...",
    merge_algorithm=MergeAlgorithm.GREEDY,  # Maximize consolidation
)
```

**How It Works:**

```python
# 1. Select minimum UTXOs needed
min_utxos = select_minimum(required_amount)

# 2. Apply merge algorithm
if merge_algorithm == "greedy":
    utxos = get_all_utxos(mixdepth)  # Add ALL remaining
elif merge_algorithm == "gradual":
    utxos = min_utxos + [smallest_remaining]  # Add 1 small UTXO
elif merge_algorithm == "random":
    extra = random.randint(0, 2)
    utxos = min_utxos + random_sample(extra)  # Add 0-2 random
```

**Privacy Trade-offs:**

- **Greedy**: Fast consolidation but reveals full UTXO set per CoinJoin
- **Gradual**: Slower consolidation but smaller transactions
- **Random**: Obfuscates intent but unpredictable consolidation rate
- **Default**: Minimum inputs but may accumulate dust UTXOs

**Key Insight:** Makers benefit from merge algorithms because takers pay the fees, but this reveals more about the maker's UTXO set. The choice depends on whether UTXO consolidation outweighs privacy concerns.

---

## Neutrino Light Client

Neutrino is a BIP157/BIP158 light client that provides privacy-preserving blockchain access without requiring a full Bitcoin node.

**The Neutrino server is maintained separately at [github.com/m0wer/neutrino-api](https://github.com/m0wer/neutrino-api).**

### Why Neutrino?

| Feature | Full Node | Traditional SPV | Neutrino SPV |
|---------|-----------|----------------|--------------|
| Storage | ~500 GB | ~50 MB | ~500 MB |
| Initial Sync | Days | Minutes | Minutes |
| Privacy | Full | Low (reveals addresses) | High (downloads filters) |
| Validation | Full | Headers only | Headers + filters |

### Architecture

The Neutrino server (written in Go) provides a REST API for wallet integration:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Neutrino Server (Go)                       │
│               github.com/m0wer/neutrino-api                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   P2P Node   │    │   Filter     │    │   REST API   │       │
│  │  (btcsuite)  │────│    Store     │────│   Handler    │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                                       │               │
│         │  BIP157/158                           │ HTTP          │
│         ▼                                       ▼               │
│  ┌──────────────┐                        ┌──────────────┐       │
│  │   Bitcoin    │                        │   Python     │       │
│  │   Network    │                        │   Backend    │       │
│  └──────────────┘                        └──────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Block Headers**: Syncs all block headers (same as traditional SPV)
2. **Compact Block Filters**: Downloads BIP158 filters for each block
3. **Filter Matching**: Checks filters locally for watched addresses
4. **Block Download**: Only downloads full blocks that match filters

### REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/status` | GET | Sync status, block height, peers |
| `/v1/utxos` | POST | Query UTXOs for addresses |
| `/v1/tx/broadcast` | POST | Broadcast transaction |
| `/v1/watch/address` | POST | Add address to watch list |
| `/v1/rescan` | POST | Rescan from specific height |
| `/v1/fees/estimate` | GET | Fee estimation |

### Usage with Docker

```bash
# Start Neutrino server using the pre-built image
docker-compose --profile neutrino up -d neutrino

# Or with full system
docker-compose --profile neutrino up -d

# Or run standalone (mainnet example)
docker run -d \
  -p 8334:8334 \
  -v neutrino-data:/data/neutrino \
  -e NETWORK=mainnet \
  -e LOG_LEVEL=info \
  ghcr.io/m0wer/neutrino-api:0.2
```

### Python Backend Integration

```python
from jmwallet.backends.neutrino import NeutrinoBackend

backend = NeutrinoBackend(
    neutrino_url="http://localhost:8334",
    network="mainnet"
)

# Wait for sync
await backend.wait_for_sync()

# Get UTXOs
utxos = await backend.get_utxos(["bc1q..."])

# Broadcast transaction
txid = await backend.broadcast_transaction(tx_hex)
```

### Privacy Benefits

Unlike traditional SPV (Bloom filters), Neutrino:
- **Never reveals addresses** to peers (downloads all filters)
- **Checks filters locally** for matches
- **Only downloads relevant blocks** when matches found
- Works well over **Tor** for additional privacy

---

## Messaging Protocol

### Message Format

All messages are JSON envelopes terminated with `\r\n`:

```json
{"type": <message_type>, "line": "<payload>"}
```

### Message Types

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

### JoinMarket Message Format

Inside the `line` field, JoinMarket messages follow this format:

```
{from_nick}!{to_nick}!{command} {arguments}
```

- `from_nick`: Sender's nickname (e.g., `J6AiXEVUkwBBZs8A`)
- `to_nick`: Recipient or `PUBLIC` for broadcasts
- `command`: Command with `!` prefix
- `arguments`: Space-separated arguments

### Nick Format

Nicks are derived from ephemeral keypairs:

```
J + version + base58(sha256(pubkey)[:10]) + padding
```

Example: `J54JdT1AFotjmpmH` (16 chars total, v5 peer)

The nick format enables:
1. Anti-spoofing via message signatures
2. Nick recovery across multiple message channels

**Note**: Our implementation uses J5 nicks for compatibility with the reference implementation. All feature detection (like `neutrino_compat`) happens via handshake features, not nick version.

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

### Peerlist Feature Extension Format

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
| `neutrino_compat` | Supports extended UTXO format with scriptPubKey and blockheight |
| `push_encrypted` | (Future) Session-bound encrypted `!push` commands |

### FeatureSet Implementation

```python
from jmcore.protocol import FeatureSet, FEATURE_NEUTRINO_COMPAT

# Create feature set
features = FeatureSet(features={FEATURE_NEUTRINO_COMPAT})

# Check support
if features.supports_neutrino_compat():
    # Use extended UTXO format
    pass

# Serialize for handshake
features_dict = features.to_dict()  # {"neutrino_compat": True}
```

### Handshake Integration

**Handshake Request** (peer → directory):
```json
{
  "proto-ver": 5,
  "features": {"neutrino_compat": true},
  ...
}
```

**Handshake Response** (directory → peer):
```json
{
  "proto-ver-min": 5,
  "proto-ver-max": 5,
  "features": {"neutrino_compat": true},
  ...
}
```

**Note**: The `features` dict is ignored by the reference implementation but preserved for our peers.

---

## Neutrino Compatibility Feature

### Overview

The `neutrino_compat` feature extends the JoinMarket protocol to support Neutrino/BIP157 light clients. The core challenge is that Neutrino clients **cannot verify arbitrary UTXOs** - they can only query UTXOs for addresses they're already watching. This breaks CoinJoin because:

- **Makers** need to verify taker's PoDLE UTXO (arbitrary lookup)
- **Takers** need to verify maker UTXOs (arbitrary lookup)

### Solution: Extended UTXO Metadata

When both peers support `neutrino_compat`, UTXO metadata (scriptPubKey and block height) is included to allow Neutrino clients to:
1. Add the scriptPubKey to their watch list
2. Rescan from the specified block height
3. Verify the UTXO exists and is unspent

### Extended UTXO Format

| Format | Fields | Example |
|--------|--------|---------|
| Legacy | `txid:vout` | `abc123...def:0` |
| Extended | `txid:vout:scriptpubkey:blockheight` | `abc123...def:0:0014abc...789:850000` |

The extended format is only used when:
1. The peer supports `neutrino_compat` feature
2. The sender's backend requires Neutrino metadata

### Modified Messages

#### `!auth` (Taker → Maker)

The PoDLE revelation UTXO field is extended:

**Legacy format**:
```
txid:vout|P|P2|sig|e
```

**Extended format (with neutrino_compat)**:
```
txid:vout:scriptpubkey:blockheight|P|P2|sig|e
```

#### `!ioauth` (Maker → Taker)

The UTXO list is extended:

**Legacy format**:
```
txid1:vout1,txid2:vout2 auth_pub cj_addr change_addr btc_sig
```

**Extended format (with neutrino_compat)**:
```
txid1:vout1:spk1:height1,txid2:vout2:spk2:height2 auth_pub cj_addr change_addr btc_sig
```

### Backward Compatibility

| Taker Backend | Maker Backend | Feature Supported | Format Used | Works? |
|---------------|---------------|-------------------|-------------|--------|
| Full Node | Full Node | N/A | Legacy | Yes |
| Full Node | Neutrino | Maker needs extended | Extended | Yes |
| Neutrino | Full Node | Taker needs extended | Extended | Yes |
| Neutrino | Neutrino | Both need extended | Extended | Yes (both must support `neutrino_compat`) |

**Important**: Neutrino-only peers can only CoinJoin with peers that support the `neutrino_compat` feature. CoinJoins with legacy-only peers will fail at UTXO verification.

### Verification Flow (Neutrino Backend)

```python
async def verify_utxo_with_metadata(
    self,
    txid: str,
    vout: int,
    scriptpubkey: str | None,
    blockheight: int | None,
    expected_scriptpubkey: str | None
) -> UTXOVerificationResult:
    # 1. Add scriptPubKey to watch list
    # 2. Rescan from blockheight (with safety margin)
    # 3. Query UTXOs for the watched address
    # 4. Verify UTXO exists and matches expected value
```

### Implementation Files

| File | Changes |
|------|---------|
| `jmcore/protocol.py` | `FeatureSet`, `FEATURE_NEUTRINO_COMPAT`, feature detection |
| `jmcore/podle.py` | Extended UTXO parsing in revelations |
| `jmwallet/backends/base.py` | `verify_utxo_with_metadata()` interface |
| `jmwallet/backends/neutrino.py` | Neutrino-specific verification |
| `maker/coinjoin.py` | Extended `!auth` parsing, extended `!ioauth` response |
| `taker/podle.py` | `ExtendedPoDLECommitment` with metadata |
| `taker/taker.py` | Extended `!auth` sending, extended `!ioauth` parsing |

---

## Neutrino Transaction Verification

### Overview

After broadcasting a CoinJoin transaction, the taker must verify that the transaction was successfully broadcast. Traditional full node backends use `get_transaction(txid)` to check mempool/blockchain, but Neutrino light clients cannot fetch arbitrary transactions by txid—they can only query UTXOs for known addresses using compact block filters.

### Solution: Universal Verification Method

The `verify_tx_output()` method works across all backend types:

- **Full Node Backends** (Bitcoin Core, Mempool API): Use `get_transaction(txid)` as before
- **Neutrino Backend**: Use address-based UTXO lookup via `/v1/utxo/{txid}/{vout}?address=...&start_height=...`

### Implementation

**Backend Interface** (`jmwallet/backends/base.py`):
```python
async def verify_tx_output(
    self,
    txid: str,
    vout: int,
    address: str,
    start_height: int | None = None,
) -> bool:
    """Verify that a specific transaction output exists (was broadcast)."""
    tx = await self.get_transaction(txid)
    return tx is not None
```

**Neutrino Override** (`jmwallet/backends/neutrino.py`):
```python
async def verify_tx_output(
    self,
    txid: str,
    vout: int,
    address: str,
    start_height: int | None = None,
) -> bool:
    """Verify output exists using neutrino's UTXO endpoint."""
    params: dict[str, str | int] = {"address": address}
    if start_height is not None:
        params["start_height"] = start_height

    result = await self._api_call("GET", f"v1/utxo/{txid}/{vout}", params=params)
    return result is not None  # Even spent outputs confirm broadcast
```

**Taker Broadcast Verification** (`taker/taker.py`):

The taker stores `cj_destination` during transaction building, finds the CJ output index from `tx_metadata`, and verifies both CJ and change outputs after broadcast:

```python
# In _broadcast_via_maker()
verified = await self.backend.verify_tx_output(
    txid=expected_txid,
    vout=taker_cj_vout,
    address=self.cj_destination,
    start_height=current_height,  # Optimization for Neutrino
)
```

### Broadcast Policy & Fallback

Taker broadcast policies (configured via `tx_broadcast`):

| Option | Behavior | Fallback on Failure |
|--------|----------|---------------------|
| `self` | Always broadcast via taker's node | N/A (no fallback needed) |
| `random-peer` | Random selection (makers + taker) | Falls back to self-broadcast |
| `not-self` | Random maker only | No fallback; manual broadcast required |

If maker broadcast fails verification within timeout, the taker follows the policy's fallback behavior.

### Neutrino API Reference

```
GET /v1/utxo/{txid}/{vout}?address={address}&start_height={height}
```

**Response (unspent)**:
```json
{"unspent": true, "value": 11516, "scriptpubkey": "0014..."}
```

**Response (spent)**:
```json
{"unspent": false, "spending_txid": "a1b2c3...", "spending_input": 0, "spending_height": 928820}
```

**Response (non-existent)**: HTTP 404

Both unspent and spent responses confirm the transaction was broadcast—only 404 indicates failure.

### Benefits

1. **Universal Compatibility**: Works with all backend types without special cases
2. **Neutrino Support**: Enables light clients to verify broadcasts using address-based lookups
3. **Privacy-Preserving**: Uses compact filters (BIP157/158) without revealing full address set
4. **Backward Compatible**: No protocol changes; works with existing makers
5. **Proper Verification**: Confirms actual broadcast, not just `!push` delivery

---

## CoinJoin Protocol Flow

### Phase 1: Orderbook Discovery

```
Taker                          Directory                        Maker
  |                                |                               |
  |--- PUBMSG !orderbook --------->|                               |
  |                                |--- Broadcast ---------------->|
  |                                |                               |
  |<------------- PRIVMSG !sw0reloffer ... (per maker) ------------|
```

### Phase 2: Fill Request

The taker sends a fill request with their NaCl encryption pubkey and PoDLE commitment:

```
Taker                                                          Maker
  |                                                               |
  |--- !fill <oid> <amount> <taker_nacl_pk> <commitment> -------->|
  |                                                               |
  |<-- !pubkey <maker_nacl_pk> <signing_pk> <sig> ----------------|
```

**Fill fields**:
- `oid`: Order ID from the offer
- `amount`: CoinJoin amount in satoshis
- `taker_nacl_pk`: Taker's NaCl public key (hex, 64 chars)
- `commitment`: PoDLE commitment = sha256(P2) (hex, 64 chars)

**Pubkey response**: The maker sends their NaCl pubkey, signed with their nick identity.

### Phase 3: Authentication (Encrypted)

After key exchange, all subsequent messages are NaCl encrypted:

```
Taker                                                          Maker
  |                                                               |
  |--- !auth <encrypted_revelation> <signing_pk> <sig> ---------->|
  |        Decrypted: txid:vout|P|P2|sig|e                        |
  |                                                               |
  |<-- !ioauth <encrypted_data> <signing_pk> <sig> ---------------|
  |        Decrypted: utxos auth_pub cj_addr change_addr btc_sig  |
```

**Auth revelation** (pipe-separated after decryption):
- `utxo_str`: The UTXO being proven (`txid:vout`)
- `P`: Public key for the UTXO (hex)
- `P2`: PoDLE commitment point = k*J (hex)
- `sig`: Schnorr signature s value (hex)
- `e`: Schnorr challenge e value (hex)

**ioauth fields** (space-separated after decryption):
- `utxo_list`: Maker's UTXOs, comma-separated
- `auth_pub`: EC pubkey from one of maker's UTXOs (for btc_sig verification)
- `cj_addr`: Maker's CoinJoin output address
- `change_addr`: Maker's change output address
- `btc_sig`: ECDSA signature of maker's NaCl pubkey (proves UTXO ownership)

### Phase 4: Transaction (Encrypted)

```
Taker                                                          Maker
  |                                                               |
  |--- !tx <encrypted_tx> <signing_pk> <sig> -------------------->|
  |        Decrypted: base64(raw_tx_bytes)                        |
  |                                                               |
  |<-- !sig <encrypted_sig> <signing_pk> <sig> -------------------|
  |        Decrypted: base64(witness_signature)                   |
  |        (one !sig message per maker input)                     |
```

### Phase 5: Broadcast

The taker:
1. Collects all maker signatures
2. Adds their own signatures to the transaction
3. Assembles the final witness data
4. Broadcasts to the Bitcoin network (see broadcast policy below)

#### Broadcast Policy

The taker controls who broadcasts the final transaction via the `tx_broadcast` config option:

| Option | Behavior | Privacy |
|--------|----------|---------|
| `self` | Always broadcast via taker's own node | Lower (taker IP linked to tx) |
| `random-peer` | Random selection from all participants (makers + taker) | Higher (plausible deniability) |
| `not-self` | Random maker only, never taker's node | Highest (taker IP never linked) |

**Default**: `random-peer`

#### Maker Selection for Broadcast

When `random-peer` or `not-self` is configured:

```python
n = len(maker_utxo_data)  # Number of makers
if tx_broadcast == 'random-peer':
    i = random.randrange(n + 1)  # 0 to n (includes self at index n)
else:
    i = random.randrange(n)      # 0 to n-1 (excludes self)

if i == n:
    push_ourselves()  # Only possible with random-peer
else:
    nick_to_use = list(maker_utxo_data.keys())[i]
```

#### Broadcast Request Message

The `!push` command requests a maker to broadcast:

```
!push <base64_encoded_transaction>
```

- **Command**: `!push`
- **Mode**: Private message (not encrypted)
- **Payload**: Base64-encoded raw transaction bytes

#### Maker Broadcast Handling

Makers broadcast "unquestioningly" without verification:

```python
def on_push_tx(self, nick, tx):
    """Broadcast unquestioningly"""
    bc_interface.pushtx(tx)
```

**Rationale**: The maker already signed this transaction, so it's valid from their perspective. Whether the broadcast succeeds or propagates is not the maker's concern.

**DoS Considerations**:
- A malicious peer could spam `!push` messages with invalid data
- **Mitigation**: Generic per-peer rate limiting (see Rate Limiting section) prevents this from being a significant attack vector
- **Trade-off**: We intentionally do NOT validate session state to maintain protocol simplicity and compatibility with reference implementation
- The rate limiter is the primary defense against !push abuse

#### Fallback Mechanism

If the chosen maker fails to broadcast (transaction not seen on network within timeout):

1. **Timeout**: Configurable via `unconfirm_timeout_sec` (default: ~60 seconds)
2. **Detection**: Taker monitors for `unconfirm_callback` trigger
3. **Fallback behavior by policy**:
   - `random-peer`: Falls back to self-broadcast via taker's own node
   - `not-self`: Transaction NOT broadcast; user must manually broadcast the hex from logs
   - `self`: N/A (always self-broadcasts initially)

```python
def handle_unbroadcast_transaction(self, txid, tx):
    if config.get('POLICY', 'tx_broadcast') == "not-self":
        # Warn user but do NOT broadcast
        log.warn("Transaction is NOT broadcast. Manual broadcast required.")
        return
    # Fall back to self-broadcast
    push_ourselves()
```

#### Privacy Considerations

Broadcasting through a random maker provides privacy because:
- Taker's IP address is not associated with the transaction at the network level
- An external observer cannot determine which participant broadcast
- With `not-self`, the taker's node never touches the final transaction

**Trade-off**: Using `not-self` requires trusting makers to broadcast. If all selected makers fail or refuse, the taker must manually broadcast, potentially compromising privacy.

#### Broadcast Failure Scenarios

In multi-party CoinJoins, broadcast failures can occur for several reasons:

| Scenario | Cause | Outcome |
|----------|-------|---------|
| **Input Already Spent** | Another maker spent their UTXO before broadcast | Transaction invalid; must restart CoinJoin |
| **Network Issues** | Maker's node disconnected or slow | May succeed if taker has fallback |
| **Fee Too Low** | Transaction conflicts with higher-fee replacement | RBF rejection; transaction won't confirm |
| **Mempool Full** | Node rejects low-fee transactions | May need to retry with higher fee |

**Input Already Spent (Race Condition)**:

This is a legitimate failure mode in collaborative transactions. When multiple makers participate in CoinJoins simultaneously, one maker's UTXO might be spent in a different transaction before the current CoinJoin is broadcast. This results in an error like:

```
RPC error -26: insufficient fee, rejecting replacement <txid>
```

This is **not a bug** - it's an expected race condition in decentralized systems. The taker should:
1. Log the failure
2. Select different makers
3. Retry the CoinJoin

**Maker Behavior on Broadcast Failure**:

Makers broadcast transactions "unquestioningly" when they receive `!push`. If broadcast fails:
- The maker logs the error but does not retry
- The taker may have configured a fallback (see Fallback Mechanism above)
- No funds are at risk since the transaction was never confirmed

### Implementation Reference

The protocol flow is implemented in:
- `taker/src/taker/taker.py` - `do_coinjoin()` method
- `maker/src/maker/bot.py` - Message handlers
- `maker/src/maker/coinjoin.py` - CoinJoin session state machine

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

---

## Encryption Protocol

Private messages containing sensitive data are encrypted using NaCl (libsodium) authenticated encryption.

### Key Exchange

```
TAK: !fill <order_id> <amount> <taker_nacl_pubkey> <commitment>
MAK: !pubkey <maker_nacl_pubkey> <signing_pk> <sig>
```

Both parties:
1. Generate ephemeral Curve25519 keypairs
2. Exchange public keys in the fill/pubkey messages
3. Derive a shared secret using ECDH
4. Create a NaCl `Box` for authenticated encryption

### NaCl Box Usage

```python
from nacl.public import PrivateKey, PublicKey, Box
import base64

# Key generation
our_keypair = PrivateKey.generate()
our_pubkey = our_keypair.public_key

# After receiving counterparty's pubkey
their_pubkey = PublicKey(bytes.fromhex(their_pubkey_hex))
box = Box(our_keypair, their_pubkey)

# Encrypt (includes authentication tag + random nonce)
plaintext = "message to encrypt"
ciphertext = box.encrypt(plaintext.encode())
encrypted_b64 = base64.b64encode(ciphertext).decode()

# Decrypt
ciphertext = base64.b64decode(encrypted_b64)
plaintext = box.decrypt(ciphertext).decode()
```

### Encrypted Messages

The following commands are always encrypted after key exchange:
- `!auth` - PoDLE revelation (pipe-separated fields)
- `!ioauth` - Maker's UTXOs and addresses (space-separated fields)
- `!tx` - Base64-encoded unsigned transaction
- `!sig` - Base64-encoded witness signature

### Anti-MITM Protection

Each party proves they control a Bitcoin key:

**Maker** (in `!ioauth`):
- Signs their **own NaCl pubkey** with an EC key from one of their UTXOs
- This `btc_sig` proves the encryption channel belongs to a real UTXO owner

**Taker** (in `!auth`):
- The PoDLE proof itself proves ownership of the committed UTXO
- The UTXO's pubkey is revealed as `P` in the revelation

This binding prevents a MITM from:
1. Intercepting the key exchange
2. Substituting their own encryption keys
3. Decrypting and re-encrypting messages

---

## PoDLE (Proof of Discrete Log Equivalence)

PoDLE prevents Sybil attacks by requiring takers to commit to a UTXO ownership proof before makers reveal their UTXOs.

### Purpose

Without PoDLE, an attacker could:
1. Request CoinJoins from many makers
2. Collect their UTXO sets
3. Never complete the transaction
4. Link maker UTXOs across requests

### Mathematical Foundation

The PoDLE proves that two points P and P2 have the same discrete logarithm (private key k) without revealing k:

- `P = k * G` (standard public key, where G is the generator)
- `P2 = k * J` (commitment point, where J is a NUMS point)

A NUMS (Nothing Up My Sleeve) point is generated deterministically such that no one knows its discrete log.

### Protocol

1. **Taker generates commitment**: `C = H(P2)` where `P2 = k*J`
   - `k` = private key for a UTXO
   - `J` = NUMS point (indexed 0-9 for reuse allowance)
   - `G` = Standard secp256k1 generator point

2. **Taker sends commitment** to maker in `!fill`

3. **Maker accepts** and sends their encryption pubkey

4. **Taker reveals** in `!auth`:
   - `P` = public key (k*G)
   - `P2` = commitment point (k*J)
   - `sig` (s), `e` = Schnorr-like proof values

5. **Maker verifies**:
   - `H(P2) == C` (commitment matches)
   - Schnorr proof is valid (see below)
   - UTXO exists and is unspent

### Schnorr Proof Details

**Generation** (taker side):
```python
# Random nonce
k_proof = random_scalar()

# Commitment points
Kg = k_proof * G
Kj = k_proof * J

# Challenge (Fiat-Shamir heuristic)
e = sha256(Kg || Kj || P || P2)  # as integer mod N

# Response (ADDITION convention)
s = (k_proof + e * k) % N
```

**Verification** (maker side):
```python
# Recover Kg using SUBTRACTION
# Since s = k_proof + e*k, we have k_proof = s - e*k
# So Kg = k_proof*G = s*G - e*k*G = s*G - e*P
minus_e = (-e) % N
Kg_check = s*G + minus_e*P  # = s*G - e*P

# Similarly for Kj
Kj_check = s*J + minus_e*P2  # = s*J - e*P2

# Verify challenge
e_check = sha256(Kg_check || Kj_check || P || P2)
assert e_check == e
```

### NUMS Point Index System

NUMS (Nothing Up My Sleeve) points are deterministically derived alternate generator points used for the PoDLE commitment. Each index (0-9) produces a **different NUMS point**, and thus a **different commitment** for the same UTXO.

**Why Different Indices Produce Different Commitments:**

```
P2 = k * J(index)

Where:
- k = UTXO private key (constant for a given UTXO)
- J(index) = NUMS point at the given index (varies per index)
- P2 = commitment point (varies per index)

Since J(0) ≠ J(1) ≠ J(2) ..., even with the same k:
- P2_0 = k * J(0) ≠ k * J(1) = P2_1
- Commitment_0 = H(P2_0) ≠ H(P2_1) = Commitment_1
```

**Index Usage Policy:**

| Index | Meaning | Action |
|-------|---------|--------|
| 0 | First use of this UTXO | Preferred by takers (fresh UTXO) |
| 1-2 | UTXO used in 1-2 failed CoinJoins | Acceptable by reference default (max_retries=3) |
| 3+ | Beyond reference default limit | Only accepted if taker configures higher max_retries |

**Configuration:**

```toml
[TAKER]
# Maximum number of PoDLE index retries per UTXO (default: 3, matches reference)
taker_utxo_retries = 3  # Allows indices 0,1,2
```

**Our Implementation (Lazy Evaluation):**

We match the reference implementation's PoDLE retry logic using an optimized lazy evaluation approach:

1. **Pre-sort UTXOs** by confirmations (descending) and value (descending)
   - Older UTXOs provide better privacy
   - Larger UTXOs provide stronger commitment

2. **Try each UTXO** in order, testing indices 0..max_retries-1 sequentially
   - Generate PoDLE commitment for the current index
   - Check if commitment has been used
   - Stop immediately when finding an unused commitment

3. **Skip to next UTXO** if all indices exhausted (retry_count >= max_retries)

4. **Commitment Tracking**: Used commitments are persisted to `~/.joinmarket-ng/cmtdata/commitments.json`

**Benefits of Lazy Evaluation:**
- Dramatically reduces PoDLE generations (1-3 instead of 15+)
- Fresh UTXOs naturally succeed faster (at index 0)
- Respects retry limits without expensive pre-computation

**Example Flow:**

```python
# UTXO_A: 30 BTC, 50 confs, fresh (no indices used)
# UTXO_B: 25 BTC, 20 confs, indices 0,1 used

# Selection with lazy evaluation:
# 1. Try UTXO_A first (50 confs > 20 confs)
#    - Try index 0 → unused! Success (1 generation)

# If UTXO_A had all indices 0,1,2 used:
# 1. Try UTXO_A: index 0 used, index 1 used, index 2 used (3 generations)
#    - All indices exhausted, skip to next UTXO
# 2. Try UTXO_B: index 0 used, index 1 used, index 2 → unused! Success (6 total)

# After 3 failed CoinJoins with UTXO_A (indices 0,1,2 used):
# UTXO_A is now exhausted (retry_count=3 >= max_retries=3)
# Next CoinJoin will use UTXO_B index 2
```

**Reference Implementation Behavior:**

The reference implementation uses `get_podle_tries()` to determine the next available index:

```python
# Reference implementation logic (simplified)
def get_podle_tries(utxo, priv, max_tries=3):
    for i in reversed(range(max_tries)):
        commitment = generate_podle(utxo, priv, index=i)
        if commitment.hash in used_commitments:
            return i + 1  # This index and below are used
    return 0  # No indices used yet

# Taker gets next available index
tries = get_podle_tries(utxo, priv, max_tries=3)
if tries >= max_tries:
    # All indices exhausted, try next UTXO
    continue
next_index = tries  # Start from lowest unused index
```

**NUMS Point Generation Algorithm:**

```python
def get_nums_point(index):
    """Generate NUMS point J(index) deterministically."""
    for G in [compressed_G, uncompressed_G]:
        seed = G + bytes([index])
        for counter in range(256):
            seed_c = seed + bytes([counter])
            x = sha256(seed_c)
            point = 0x02 + x  # Try even y-coordinate
            if is_valid_curve_point(point):
                return point
```

The precomputed NUMS points for indices 0-9 are hardcoded to avoid recomputation.

### UTXO Selection for PoDLE

Not all UTXOs are suitable for PoDLE commitments. The selection criteria ensure the commitment is credible and the UTXO is economically significant.

**Eligibility Criteria:**

| Criterion | Default | Rationale |
|-----------|---------|-----------|
| Minimum confirmations | 5 | Prevents double-spend attacks |
| Minimum value (% of cj_amount) | 20% | Ensures economic stake |

**Selection Priority:**

UTXOs are sorted by preference (highest priority first):
1. **Confirmations** (descending): Older UTXOs are more trustworthy
2. **Value** (descending): Larger UTXOs show more skin in the game

**Implementation:**

```python
# taker/src/taker/podle.py
def get_eligible_podle_utxos(utxos, cj_amount, min_confirmations=5, min_percent=20):
    min_value = cj_amount * min_percent / 100
    eligible = [u for u in utxos
                if u.confirmations >= min_confirmations
                and u.value >= min_value]
    eligible.sort(key=lambda u: (u.confirmations, u.value), reverse=True)
    return eligible
```

**Important:** The UTXO used for PoDLE commitment should generally also be included as an input in the CoinJoin transaction, as it proves the taker controls funds being mixed.

### Taker Commitment Tracking

Takers must track which commitments they've used to avoid reusing the same commitment with different makers. This is stored locally in `cmtdata/commitments.json`.

**File Format:**

```json
{
  "used": [
    "abc123...",  // H(P2) commitment hashes (hex)
    "def456..."
  ],
  "external": {}  // Reserved for external commitment sources
}
```

**File Location:**
- `~/.joinmarket-ng/cmtdata/commitments.json` (or `$JOINMARKET_DATA_DIR/cmtdata/commitments.json`)

**Tracking Flow:**

```
1. Taker prepares CoinJoin
2. For each eligible UTXO (sorted by preference):
   a. For each index (0-9):
      - Generate commitment C = H(k * J(index))
      - Check: is C in local used commitments?
      - If not used: SELECT THIS, mark as used, save to file
      - If used: try next index
   b. If all indices exhausted: try next UTXO
3. If no fresh commitment found: ERROR (need to wait for new UTXOs)
```

**Why Track Locally?**

Even if a CoinJoin fails before `!auth` is sent, the taker should not reuse that commitment with a different maker—it could reveal linkage patterns.

**Implementation Reference:**

```python
# taker/src/taker/podle_manager.py
class PoDLEManager:
    def generate_fresh_commitment(self, wallet_utxos, cj_amount, private_key_getter):
        for utxo in get_eligible_podle_utxos(wallet_utxos, cj_amount):
            for index in range(10):
                commitment = generate_podle(privkey, utxo, index)
                if commitment.hash not in self.used_commitments:
                    self.used_commitments.add(commitment.hash)
                    self._save()
                    return commitment
        return None  # All commitments exhausted
```

### Maker Commitment Blacklist

Makers maintain a network-wide blacklist of commitments received via `!hp2` messages. This prevents the same commitment from being accepted by multiple makers.

**File:** `cmtdata/commitmentlist` (one commitment hash per line)

**Key Difference from Taker Tracking:**

| Aspect | Taker Tracking | Maker Blacklist |
|--------|---------------|-----------------|
| File | `commitments.json` | `commitmentlist` |
| Scope | Local (my own commitments) | Network-wide (all commitments) |
| Source | Generated locally | Received via `!hp2` |
| Purpose | Prevent self-reuse | Prevent network reuse |

**When Makers Add to Blacklist:**

1. **After successful `!auth` verification**: The maker broadcasts `!hp2` and adds to local blacklist
2. **On receiving `!hp2` broadcast**: Add to blacklist (even without verifying the CoinJoin)

### Commitment Retry Logic

When a CoinJoin fails (e.g., maker offline, transaction timeout), the taker can retry with a fresh commitment.

**Retry Strategy:**

```
Attempt 1: UTXO_A, index 0 → fails
Attempt 2: UTXO_A, index 1 → fails (same UTXO, different index)
Attempt 3: UTXO_A, index 2 → fails
...
Attempt 10: UTXO_A, index 9 → fails (all indices exhausted)
Attempt 11: UTXO_B, index 0 → success (different UTXO)
```

**Why This Works:**

1. **Different index = different commitment**: `H(k * J(0)) ≠ H(k * J(1))`
2. **Maker rejection by index**: Makers may configure `max_tries` to reject high indices
3. **UTXO rotation**: When all indices are exhausted, use a different UTXO

**Configuration:**

```python
# Taker config
min_podle_confirmations: int = 5   # Minimum UTXO age
min_podle_percent: int = 20        # Minimum UTXO value as % of cj_amount

# Maker config (reference implementation)
taker_utxo_retries: int = 3        # Max index accepted (0-2)
```

### Implementation Reference

```python
# jmcore/src/jmcore/podle.py

def generate_podle(private_key_bytes, utxo_str, index=0) -> PoDLECommitment:
    """Generate PoDLE commitment for a UTXO."""

def verify_podle(p, p2, sig, e, commitment, index_range) -> tuple[bool, str]:
    """Verify PoDLE proof."""
```

### Commitment Blacklisting and hp2 Protocol

Once a PoDLE commitment has been used (whether the CoinJoin succeeds or fails), it should be blacklisted to prevent reuse. The `!hp2` command broadcasts commitments across the maker network for collective blacklisting.

#### Message Format

```
!hp2 <commitment_hex>
```

Where `commitment_hex` is the SHA256 hash of the P2 point (64 hex characters).

#### Broadcast Flow

1. **After !auth verification**: When a maker successfully verifies a taker's PoDLE proof, it broadcasts the commitment via `!hp2` as a **public message** (PUBMSG)

2. **On receiving !hp2 via PUBMSG**: Makers add the commitment to their local blacklist and reject any future `!fill` requests using that commitment

3. **On receiving !hp2 via PRIVMSG**: Another maker is asking us to broadcast the commitment on their behalf (for source obfuscation). We re-broadcast it publicly without verification.

#### Source Obfuscation

To prevent observers from identifying which maker first saw a commitment, makers can send `!hp2` via PRIVMSG to a random peer, asking them to broadcast it publicly. This provides plausible deniability about which maker processed the original CoinJoin.

```
Maker A (processes CoinJoin) → PRIVMSG !hp2 → Maker B (random)
                                              ↓
                                        PUBMSG !hp2 → All makers
```

#### Why Blacklist Commitments?

- **Anti-Sybil**: Prevents attackers from reusing the same UTXO proof to harvest maker UTXOs
- **Failed CoinJoin Protection**: Even if a CoinJoin fails, the commitment is burned
- **Network Coordination**: Distributed blacklist across all makers

#### Implementation Details

The blacklist is persisted to a `commitmentlist` file (one commitment per line, ASCII format). The location is:

- **Direct Python**: `~/.joinmarket-ng/cmtdata/commitmentlist` (or `$JOINMARKET_DATA_DIR/cmtdata/commitmentlist`)
- **Docker**: `/home/jm/.joinmarket/cmtdata/commitmentlist` (mounted as volume)

This matches the reference implementation's subdirectory structure (`cmtdata/`) for compatibility.

The blacklist implementation is:

- **Thread-safe**: Uses file locking for concurrent access
- **Case-insensitive**: Commitments are normalized to lowercase
- **Atomic**: Check-and-add operations prevent race conditions
- **Shared**: Makers and takers on the same machine share the same blacklist file

Commitments are added to the blacklist:
1. When received via `!hp2` public broadcast
2. When broadcasting our own commitment after successful `!auth`

---

## Fidelity Bonds

Fidelity bonds allow makers to prove they have locked bitcoins, improving trust and selection probability.

### Bond Proof Structure

The bond proof is 252 bytes, packed in little-endian format:

```
Field           Size    Description
─────────────────────────────────────────────────────────────────────────
nick_sig        72      Nick signature (padded DER)
cert_sig        72      Certificate signature (padded DER)
cert_pub        33      Certificate public key (compressed)
cert_expiry      2      Certificate expiry (blocks / 2016)
utxo_pub        33      UTXO public key (compressed)
txid            32      Bond UTXO txid (little-endian)
vout             4      Bond UTXO output index
locktime         4      Bond locktime (Unix timestamp)
─────────────────────────────────────────────────────────────────────────
Total          252      Base64-encoded for transmission
```

### Signature Padding

DER signatures are typically 70-72 bytes. The reference implementation pads to exactly 72 bytes using **leading 0xff bytes**:

```python
# Padding (generation)
padded_sig = signature_der.rjust(72, b'\xff')

# Stripping (verification) - find DER header 0x30
stripped_sig = padded_sig[padded_sig.index(b'\x30'):]
```

**Important**: This is leading padding (rjust), not trailing padding. The verifier finds the DER sequence header (0x30) to locate the actual signature start.

### Message Formats

Both signatures use **Bitcoin message signing format** (double SHA256 with prefix):

```python
def bitcoin_message_hash(message: bytes) -> bytes:
    prefix = b"\x18Bitcoin Signed Message:\n"
    varint = bytes([len(message)])  # simplified for short messages
    full_msg = prefix + varint + message
    return sha256(sha256(full_msg).digest()).digest()
```

#### Nick Signature

Proves the maker controls the certificate key. Signs `(taker_nick|maker_nick)`:

```
Message: (taker_nick + '|' + maker_nick).encode('ascii')
Example: b'J5testtaker|J5testmaker'
Signer:  Certificate private key (cert_pub)
```

The nick signature is **taker-specific** - each taker receives a unique proof.

#### Certificate Signature

Self-signed certificate binding the certificate key to the UTXO. Two formats are accepted for backward compatibility:

**Binary format** (preferred):
```
Message: b'fidelity-bond-cert|' + cert_pub + b'|' + str(cert_expiry_encoded).encode('ascii')
Example: b'fidelity-bond-cert|\x02\xae...(33 bytes)...|52'
Signer:  UTXO private key (utxo_pub)
```

**ASCII format** (legacy):
```
Message: b'fidelity-bond-cert|' + hexlify(cert_pub) + b'|' + str(cert_expiry_encoded).encode('ascii')
Example: b'fidelity-bond-cert|02ae52...(66 chars)...|52'
Signer:  UTXO private key (utxo_pub)
```

Note: `cert_expiry_encoded` is `cert_expiry_blocks // 2016`, not the raw block count.

### Certificate Chain

```
UTXO keypair ────signs────► certificate ────signs────► nick proofs
(cold storage)              (hot wallet)              (per-taker)
```

The two-signature scheme allows:
1. Cold storage of the fidelity bond private key
2. Hot wallet holds only the certificate keypair
3. Certificate expiry limits exposure if hot wallet is compromised

For **self-signed certificates** (common case): `cert_pub == utxo_pub`

### Bond Value Calculation

Bond value depends on:
- Amount of locked bitcoin
- Time until unlock (longer = more valuable)
- Current confirmation count

### Verification Flow

```python
def verify_fidelity_bond_proof(proof_base64, maker_nick, taker_nick):
    # 1. Decode and unpack the 252-byte proof
    decoded = base64.b64decode(proof_base64)
    nick_sig, cert_sig, cert_pub, cert_expiry_encoded, utxo_pub, txid, vout, locktime = \
        struct.unpack("<72s72s33sH33s32sII", decoded)

    # 2. Strip 0xff padding from signatures
    nick_sig_stripped = nick_sig[nick_sig.index(b'\x30'):]
    cert_sig_stripped = cert_sig[cert_sig.index(b'\x30'):]

    # 3. Verify nick signature (proves maker identity)
    nick_msg = (taker_nick + '|' + maker_nick).encode('ascii')
    verify_bitcoin_message_signature(nick_msg, nick_sig_stripped, cert_pub)

    # 4. Verify certificate signature (proves UTXO ownership)
    cert_msg = b'fidelity-bond-cert|' + cert_pub + b'|' + str(cert_expiry_encoded).encode('ascii')
    verify_bitcoin_message_signature(cert_msg, cert_sig_stripped, utxo_pub)

    # 5. Verify UTXO exists on-chain (external lookup)
    # ...
```

### Nick Signature Context (PUBMSG vs PRIVMSG)

The `taker_nick` used for verification depends on the context:

- **Public Offers (PUBMSG)**: The maker self-signs the proof using their own nick as `taker_nick`.
  - Verifier uses: `verify_fidelity_bond_proof(proof, maker_nick, maker_nick)`

- **Private Offers (PRIVMSG)**: The maker signs the proof specifically for the requesting taker.
  - Verifier uses: `verify_fidelity_bond_proof(proof, maker_nick, my_nick)`

This distinction is crucial for interoperability with reference implementation makers, which respond to `!orderbook` via PRIVMSG.

### Public Key Disclosure and Quantum Computing Considerations

**Public Key Visibility**: The fidelity bond's public key is disclosed in the P2P orderbook, not on the blockchain.

**How it works**:
1. On-chain, the bond is a P2WSH (Pay-to-Witness-Script-Hash) output containing only `SHA256(witness_script)`
2. To allow takers to verify bonds, makers broadcast the full witness script off-chain:
   ```
   <expiry_time> OP_CHECKLOCKTIMEVERIFY OP_DROP <PUBKEY> OP_CHECKSIG
   ```
3. Takers extract the `<PUBKEY>` and `<expiry_time>`, reconstruct the script, and verify the hash matches the on-chain UTXO

**Why this is necessary**: Takers need to:
- Verify the bond exists on-chain
- Calculate bond value from amount and locktime
- Verify the maker owns the bond (via message signature)

**Theoretical quantum computing risk**:
- The public key is visible in the orderbook (not the blockchain)
- In theory, a sufficiently powerful quantum computer running Shor's algorithm could derive the private key
- Maximum bond duration is 10 years, which could coincide with quantum computing advances (purely speculative)
- Upon bond expiry, the public key becomes visible on-chain when spending the UTXO

**Practical considerations**:
- No evidence that quantum computing poses an imminent threat to Bitcoin
- Satoshi's coins serve as a "canary" - they would likely be targeted first
- Bitcoin will likely implement quantum-resistant signatures network-wide before this becomes a real concern
- Bond value is evaluated from on-chain data (amount, locktime), not identity, so rotating addresses is possible

**Alternative design tradeoffs**: The bond verification data could be shared only during encrypted taker-maker negotiation rather than in the public orderbook, but this would:
- Prevent takers from pre-filtering fake/invalid bonds
- Add complexity without meaningful security improvement
- Not address the fundamental issue (public key visible somewhere off-chain)

---

## Transaction Types

### Standard CoinJoin (CJMTx)

```
Inputs:                          Outputs:
  Taker UTXO 1                     CJ Output (Taker dest) ──► equal
  Taker UTXO 2                     CJ Output (Maker 1)    ──► equal
  Maker 1 UTXO                     CJ Output (Maker 2)    ──► equal
  Maker 2 UTXO                     Taker Change
                                   Maker 1 Change
                                   Maker 2 Change
```

### Sweep Transaction (SweepJMTx)

The taker consumes **all** UTXOs from a mixdepth:
- No taker change output
- Typically used as final tumbler step

### Key Implementation Details

**BIP 143 Sighash (P2WPKH)**

The scriptCode for P2WPKH is 25 bytes:
```
OP_DUP OP_HASH160 <20-byte-pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
```

**Low-S Signature Normalization (BIP 62/146)**

```python
secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1_half_order = secp256k1_order // 2

if s > secp256k1_half_order:
    s = secp256k1_order - s
```

**Input Index Mapping**

CoinJoin inputs are shuffled for privacy. Makers must find their actual input indices:

```python
input_index_map = {}
for idx, inp in enumerate(tx.inputs):
    txid = inp.txid_le[::-1].hex()  # Convert LE to BE
    input_index_map[(txid, inp.vout)] = idx
```

---

## Offer System

### Offer Types

| Type | Fee Structure |
|------|--------------|
| `sw0absoffer` | Absolute fee in satoshis |
| `sw0reloffer` | Relative fee (e.g., 0.000014 = 14 ppm) |

### Offer Fields

1. `oid` - Order ID (integer)
2. `minsize` - Minimum CoinJoin amount (satoshis)
3. `maxsize` - Maximum CoinJoin amount (satoshis)
4. `txfee` - Transaction fee contribution (satoshis)
5. `cjfee` - CoinJoin fee (satoshis or decimal)

### Fee Calculation

```python
def calculate_cj_fee(offer: Offer, cj_amount: int) -> int:
    if offer.ordertype == OrderType.SW0RELOFFER:
        return int(cj_amount * offer.cjfee)
    else:
        return int(offer.cjfee)
```

---

## Tor Integration

JoinMarket components use Tor in different ways depending on their role:

### Component Tor Requirements Summary

| Component | Needs SOCKS? | Needs Hidden Service? | Notes |
|-----------|-------------|----------------------|-------|
| **Directory Server** | ❌ No | ✅ Yes (permanent) | Tor-agnostic; only receives connections |
| **Maker** | ✅ Yes | ✅ Yes (ephemeral recommended) | Outgoing + incoming connections |
| **Taker** | ✅ Yes | ❌ No | Only outgoing connections |
| **Orderbook Watcher** | ✅ Yes | ❌ No | Only outgoing connections |

### Directory Server

Directory servers are **Tor-agnostic** - they only receive incoming connections through their hidden service. They do NOT make outgoing connections and therefore do NOT need:
- ❌ Tor SOCKS proxy configuration
- ❌ Tor control port access
- ✅ Only need a **permanent** hidden service configured in `torrc`

**Why permanent?** Users need stable `.onion` addresses to save in their configs.

**torrc configuration**:
```
HiddenServiceDir /var/lib/tor/directory_hs
HiddenServiceVersion 3
HiddenServicePort 5222 directory_server:5222
```

The directory server listens on a regular TCP socket. Tor forwards incoming connections from the hidden service to this socket.

### Maker Bots

Makers need **both** SOCKS proxy (for outgoing connections to directories) and a hidden service (for direct peer connections from takers).

#### SOCKS Proxy (Outgoing)

Connect to directory servers through Tor:

```python
from maker.config import MakerConfig

config = MakerConfig(
    mnemonic="...",
    socks_host="127.0.0.1",  # Tor SOCKS proxy
    socks_port=9050,
)
```

#### Ephemeral Hidden Service (Incoming)

**Recommended approach**: Create a fresh `.onion` address each time the maker starts using Tor's control port.

**Benefits**:
- Generates a fresh identity per session
- Better privacy (no persistent fingerprint)
- No hidden service keys on disk
- Automatically cleans up when stopped

**torrc**:
```
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
```

**Maker Config**:
```python
from maker.config import MakerConfig, TorControlConfig

config = MakerConfig(
    mnemonic="...",
    socks_host="127.0.0.1",
    socks_port=9050,
    onion_serving_host="127.0.0.1",
    onion_serving_port=27183,
    tor_control=TorControlConfig(
        enabled=True,
        host="127.0.0.1",
        port=9051,
        cookie_path="/var/lib/tor/control_auth_cookie",
    ),
)
```

The maker will:
1. Connect to Tor control port at startup
2. Authenticate using the cookie file
3. Create an ephemeral hidden service via `ADD_ONION`
4. Advertise the generated `.onion` address to directory servers
5. Remove the hidden service when stopped (automatic)

### Taker Bots & Orderbook Watchers

Takers and orderbook watchers only make **outgoing** connections - they do NOT serve a hidden service.

**SOCKS Proxy Configuration**:
```python
from taker.config import TakerConfig

config = TakerConfig(
    mnemonic="...",
    socks_host="127.0.0.1",  # Tor SOCKS proxy
    socks_port=9050,
)
```

They advertise `NOT-SERVING-ONION` in their handshake because they don't accept incoming connections.

**torrc** (minimal):
```
SocksPort 0.0.0.0:9050
```

### Tor Control Protocol

The implementation uses Tor's control protocol (spec v1) for ephemeral hidden services:

- **Cookie Authentication**: Reads the 32-byte cookie from `CookieAuthFile`
- **GETINFO**: Query Tor version and status
- **ADD_ONION**: Create ephemeral v3 hidden services with ED25519-V3 keys
- **DEL_ONION**: Manually remove hidden services (optional, auto-removed on disconnect)

**Example Control Port Usage**:
```python
from jmcore.tor_control import TorControlClient

async with TorControlClient(
    control_host="127.0.0.1",
    control_port=9051,
    cookie_path="/var/lib/tor/control_auth_cookie",
) as client:
    # Get Tor version
    version = await client.get_version()
    print(f"Connected to Tor {version}")

    # Create ephemeral hidden service
    hs = await client.create_ephemeral_hidden_service(
        ports=[(27183, "127.0.0.1:27183")],
        discard_pk=True,  # Don't need the private key
    )
    print(f"Hidden service: {hs.onion_address}")

    # Service exists while connection is open
    # Automatically removed when context exits
```

### Privacy Considerations

**Ephemeral Hidden Services (Recommended for ALL makers)**:
- ✅ Fresh identity per session (better privacy)
- ✅ No persistent keys on disk
- ✅ Automatic cleanup
- ✅ Works with fidelity bonds (bond value is evaluated from on-chain data, not identity)

**Permanent Hidden Services** (directory servers only):
- ✅ Stable address for user configs
- ❌ Persistent identity (lower privacy)
- ❌ NOT recommended for makers

**Note on Fidelity Bonds**: Fidelity bond value is calculated from on-chain UTXO properties (amount, locktime, confirmations), NOT from the maker's nick or onion address. Changing your onion address each session does NOT affect your bond's value or trustworthiness.

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
| **Partitioning** | Split network by returning different peer lists | Cross-directory consistency checks (future) |
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

## References

- [Original JoinMarket Implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/)
- [JoinMarket Protocol Documentation](https://github.com/JoinMarket-Org/JoinMarket-Docs)
- [PoDLE Design](https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8)
- [Fidelity Bonds Design](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af)
- [BIP157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP158 - Compact Block Filters](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
