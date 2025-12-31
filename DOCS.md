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

JoinMarket NG supports two blockchain backends with different tradeoffs:

### Bitcoin Core Backend

- **Method**: `scantxoutset` RPC (no wallet required)
- **Requirements**: Bitcoin Core v30+
- **Validation**: Full validation
- **Storage**: ~500 GB
- **Privacy**: High (local node)

### Neutrino Backend

- **Method**: BIP157/158 compact block filters
- **Requirements**: [neutrino-api server](https://github.com/m0wer/neutrino-api) (Go)
- **Validation**: Headers + filters
- **Storage**: ~500 MB
- **Privacy**: High (downloads filters, not addresses)
- **Sync**: Minutes instead of days

**Decision Matrix**:
- Use Core if: You run a full node, need full validation
- Use Neutrino if: Limited storage, fast setup, light client needed

### Neutrino Compatibility Feature

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

### Transaction Verification

After broadcasting, takers verify the transaction was accepted:

- **Core/Mempool backends**: Use `get_transaction(txid)`
- **Neutrino backend**: Use address-based UTXO lookup at `/v1/utxo/{txid}/{vout}?address=...`

Both spent and unspent responses confirm broadcast success.

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

## CoinJoin Protocol Flow

All protocol commands use JSON-line format: `{"type": <code>, "line": "<payload>"}\r\n`

### Protocol Commands

| Command | Encrypted | Phase | Description |
|---------|-----------|-------|-------------|
| `!orderbook` | No | 1 | Request offers from makers |
| `!sw0reloffer`, `!sw0absoffer` | No | 1 | Maker offer responses (via PRIVMSG) |
| `!fill` | No | 2 | Taker fills offer with NaCl pubkey + PoDLE commitment |
| `!pubkey` | No | 2 | Maker responds with NaCl pubkey |
| `!auth` | Yes | 3 | Taker reveals PoDLE proof (encrypted) |
| `!ioauth` | Yes | 3 | Maker sends UTXOs + addresses (encrypted) |
| `!tx` | Yes | 4 | Taker sends unsigned transaction (encrypted) |
| `!sig` | Yes | 4 | Maker signs inputs (encrypted, one per input) |
| `!push` | No | 5 | Request maker to broadcast transaction |

### Phase 1: Orderbook Discovery

Taker broadcasts `!orderbook` via PUBMSG. Makers respond with offers via PRIVMSG (not PUBMSG).

### Phase 2: Fill Request

Taker sends `!fill <oid> <amount> <taker_nacl_pk> <commitment>`. Maker responds with `!pubkey <maker_nacl_pk> <signing_pk> <sig>`.

After key exchange, a NaCl `Box` is created for authenticated encryption.

### Phase 3: Authentication (Encrypted)

Taker sends `!auth` with encrypted PoDLE revelation: `txid:vout|P|P2|sig|e` (pipe-separated). With `neutrino_compat`, UTXO format extends to `txid:vout:spk:height`.

Maker verifies PoDLE, then sends `!ioauth` with encrypted data: `utxos auth_pub cj_addr change_addr btc_sig` (space-separated).

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

252-byte proof containing two signatures + metadata:

- **Nick signature** (72 bytes): Proves maker controls certificate key (signs `taker_nick|maker_nick`)
- **Certificate signature** (72 bytes): Self-signs certificate binding cert key to UTXO (signs `fidelity-bond-cert|cert_pub|expiry`)
- **Certificate pubkey** (33 bytes): Hot wallet key
- **UTXO pubkey** (33 bytes): Cold storage key (can equal cert_pub for self-signed)
- **UTXO identifiers** (txid, vout, locktime): On-chain bond location

DER signatures are padded to 72 bytes with leading `0xff` bytes.

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

### Protocol: Bond Announcement

Fidelity bonds are only sent via PRIVMSG as a direct response to `!orderbook` requests. They are not included in the initial PUBLIC offer announcements. The reference orderbook watcher only requests offers once on startup, so any offer posted afterwards does not show a bond. This does not affect takers who will always receive bond proofs when they request the orderbook.

The Nick Signature binds the bond proof to the specific taker, preventing replay attacks.
---

## Transaction Policies

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
