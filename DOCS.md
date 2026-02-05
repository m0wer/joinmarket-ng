# JoinMarket NG Technical Documentation

This document covers the JoinMarket protocol, implementation architecture, security model, and development guide.

**Table of Contents**

1. [Concepts](#concepts) - What is CoinJoin and JoinMarket
2. [JoinMarket-NG](#joinmarket-ng) - This implementation vs reference
3. [Architecture](#architecture) - System design and components
4. [Protocol](#protocol) - Transport, messages, CoinJoin flow
5. [Privacy Mechanisms](#privacy-mechanisms) - PoDLE, fidelity bonds, mixdepths
6. [Wallet](#wallet) - HD structure, UTXO selection, backends
7. [Configuration](#configuration) - Config files, Tor, notifications
8. [Security](#security) - Threat model, defenses, verification
9. [Development](#development) - Testing, dependencies, builds
10. [Best Practices](#best-practices) - Privacy tips for users
11. [References](#references) - External resources

---

## Concepts

### What is CoinJoin

CoinJoin transactions combine multiple users' funds into a single transaction, making it difficult to trace coins. This enhances financial privacy.

The transaction includes several equal amount outputs from inputs belonging to different users. An outside observer cannot determine which input corresponds to which equal amount output, effectively obfuscating the transaction history.

Change outputs are also included, but they are of different amounts and can be easily identified as change and sometimes matched to inputs using heuristics. However, the equal amount outputs remain ambiguous.

One round of CoinJoin increases privacy, but generally multiple rounds are needed to achieve strong anonymity.

### Makers and Takers

JoinMarket connects users who want to mix their coins (takers) with those willing to provide liquidity for a fee (makers):

- **Makers**: Liquidity providers who offer their UTXOs for CoinJoin and earn fees. They run bots that automatically participate when selected.
- **Takers**: Users who initiate CoinJoins by selecting makers and coordinating the transaction. They pay fees for the privacy service.

### Why JoinMarket is Different

Unlike other CoinJoin implementations (Wasabi, Whirlpool), JoinMarket has **no central coordinator**:

- **Taker acts as coordinator**: Chooses peers, gains maximum privacy (doesn't share inputs/outputs with a centralized party)
- **Most censorship-resistant**: Directory servers are easily replaceable and don't route communications, only host the orderbook
- **Multiple fallbacks**: Works with Tor hidden services, can easily move to alternatives like Nostr relays
- **Peer-to-peer**: Direct encrypted communication between participants

### Key Design Principles

1. **Trustless**: No central coordinator; the taker constructs the transaction
2. **Privacy-preserving**: End-to-end encryption for sensitive data
3. **Sybil-resistant**: PoDLE commitments prevent costless DOS attacks
4. **Decentralized**: Multiple redundant directory servers for message routing

### Why Financial Privacy Matters

Just as you wouldn't want your employer to see your bank balance when paying you, or a friend to know your net worth when splitting a bill, Bitcoin users deserve financial privacy. JoinMarket helps individuals exercise their right to financial freedom without promoting illegal activities.

---

## JoinMarket-NG

### vs Reference Implementation

This is a modern alternative implementation of the JoinMarket protocol, maintaining **full wire protocol compatibility** with the [reference implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/) while offering significant improvements.

### Key Advantages

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

### Why a New Implementation

The reference implementation has served the community well, but faces challenges that make improvements difficult:
- Limited active development (maintenance mode)
- 181+ open issues and 41+ open pull requests
- Technical debt requiring full rewrites
- Tight coupling to Bitcoin Core's BerkeleyDB

Starting fresh let us build on modern foundations while honoring the protocol's proven design. This project currently lacks peer review (contributions welcome!), but the extensive test suite and clear documentation make auditing straightforward.

**We see this as our turn to take JoinMarket to the next level while honoring the foundation built by the original contributors.**

### Compatibility

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
| Full node | No `neutrino_compat` (legacy) | Works - sends legacy UTXO format |
| Full node | Has `neutrino_compat` | Works - sends extended UTXO format |
| Neutrino | No `neutrino_compat` (legacy) | Incompatible - taker filters out |
| Neutrino | Has `neutrino_compat` | Works - both use extended format |

Neutrino takers automatically filter out makers that don't advertise `neutrino_compat` since they require extended UTXO metadata for verification.

### Roadmap

All components are fully implemented. Future work will focus on improvements, optimizations, and protocol extensions:

- Nostr relays for offer broadcasting
- CoinJoinXT and Lightning Network integration: https://www.youtube.com/watch?v=YS0MksuMl9k

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

### Components

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

### Data Directory

JoinMarket NG uses a dedicated data directory for persistent files shared across sessions.

**Location:**
- Default: `~/.joinmarket-ng`
- Override: `--data-dir` CLI flag or `$JOINMARKET_DATA_DIR` environment variable
- Docker: `/home/jm/.joinmarket-ng` (mounted as volume)

**Structure:**

```
~/.joinmarket-ng/
├── config.toml            # Configuration file
├── cmtdata/
│   ├── commitmentlist     # PoDLE commitment blacklist (makers)
│   └── commitments.json   # PoDLE used commitments (takers)
├── state/
│   ├── maker.nick         # Current maker nick
│   ├── taker.nick         # Current taker nick
│   ├── directory.nick     # Current directory server nick
│   └── orderbook.nick     # Current orderbook watcher nick
├── coinjoin_history.csv   # Transaction history log
└── fidelity_bonds.json    # Bond registry
```

**Shared Files:**

| File | Used By | Purpose |
|------|---------|---------|
| `cmtdata/commitmentlist` | Makers | Network-wide blacklisted PoDLE commitments |
| `cmtdata/commitments.json` | Takers | Locally used commitments (prevents reuse) |
| `coinjoin_history.csv` | Both | Transaction history with confirmation tracking |
| `state/*.nick` | All | Component nick files for self-CoinJoin protection |

**Nick State Files:**

Written at startup, deleted on shutdown. Used for:
- External monitoring of running bots
- Startup notifications with nick identification
- **Self-CoinJoin Protection**: Taker reads `state/maker.nick` to exclude own maker; maker reads `state/taker.nick` to reject own taker

**CoinJoin History:**

Records all CoinJoin transactions with:
- Pending transaction tracking (initially `success=False`, updated on confirmation)
- Automatic txid discovery for makers who didn't receive the final transaction
- Address blacklisting for privacy (addresses recorded before being shared with peers)
- CSV format for analysis: `jm-wallet history --stats`

---

## Protocol

### Transport Layer

All messages use JSON-line envelopes terminated with `\r\n`:

```json
{"type": <message_type>, "line": "<payload>"}
```

**Message Types:**

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

### JoinMarket Messages

Inside the `line` field of PRIVMSG/PUBMSG, JoinMarket messages follow this format:

```
!command [[field1] [field2] ...]
```

For private messages with routing:

```
{from_nick}!{to_nick}!{command} {arguments}
```

Fields are separated by **single whitespace** (multiple spaces not allowed).

### CoinJoin Flow

**Protocol Commands:**

| Command | Encrypted | Plaintext OK | Phase | Description |
|---------|-----------|--------------|-------|-------------|
| `!orderbook` | No | Yes | 1 | Request offers from makers |
| `!reloffer`, `!absoffer` | No | Yes | 1 | Maker offer responses (via PRIVMSG) |
| `!fill` | No | Yes | 2 | Taker fills offer with NaCl pubkey + PoDLE commitment |
| `!pubkey` | No | Yes | 2 | Maker responds with NaCl pubkey |
| `!error` | No | Yes | Any | Error notification |
| `!push` | No | Yes | 5 | Request maker to broadcast transaction |
| `!tbond` | No | Yes | 1 | Fidelity bond proof (with offers) |
| `!auth` | **Yes** | No | 3 | Taker reveals PoDLE proof (encrypted) |
| `!ioauth` | **Yes** | No | 3 | Maker sends UTXOs + addresses (encrypted) |
| `!tx` | **Yes** | No | 4 | Taker sends unsigned transaction (encrypted) |
| `!sig` | **Yes** | No | 4 | Maker signs inputs (encrypted, one per input) |

**Note**: Rules enforced at message_channel layer. All encrypted messages are base64-encoded.

**Phase 1: Orderbook Discovery**

1. Taker connects to directory servers
2. Sends `!orderbook` request (public broadcast)
3. Makers respond via PRIVMSG with `!reloffer` or `!absoffer`
4. Taker collects offers, filters stale/incompatible, selects makers

**Phase 2: Fill Request**

1. Taker sends `!fill` with: order ID, amount, NaCl pubkey, PoDLE commitment
2. Selected makers respond with `!pubkey` (their NaCl pubkey)
3. From here, all messages are NaCl encrypted

**Phase 3: Authentication**

1. Taker sends `!auth`: reveals PoDLE proof, UTXO info, CoinJoin destination
2. Maker verifies PoDLE, broadcasts `!hp2` to blacklist commitment
3. Maker sends `!ioauth`: their UTXOs + CoinJoin/change destinations

**Phase 4: Transaction Signing**

1. Taker builds unsigned transaction with all inputs/outputs
2. Sends `!tx` to each maker
3. Makers verify transaction (critical security checks), sign, return `!sig`
4. Taker assembles fully signed transaction

**Phase 5: Broadcast**

Broadcast policies (configurable):

| Policy | Behavior |
|--------|----------|
| `SELF` | Broadcast via own backend |
| `RANDOM_PEER` | Try makers sequentially, fall back to self |
| `MULTIPLE_PEERS` | Broadcast to N random makers (default 3), fall back to self |
| `NOT_SELF` | Try makers only, no fallback |

Default is `MULTIPLE_PEERS` for redundancy.

### Direct vs Relay Connections

JoinMarket supports two routing modes:

**Direct Peer Connections (Preferred):**
- Taker connects directly to maker's onion address
- Bypasses directory for private messages
- Better privacy (directory doesn't see message metadata)
- Lower latency after initial connection
- Default behavior (`prefer_direct_connections=True`)

**Directory Relay (Fallback):**
- Messages routed through directory servers
- Works when direct connection fails
- Higher latency, directory sees metadata
- Reliable fallback for restrictive networks

**Channel Consistency:** Once a channel is established for a session, all subsequent messages must use the same channel. This prevents session confusion attacks.

### Nick Format

Nicks are derived from ephemeral keypairs:

```
J + version + base58(sha256(pubkey)[:14])
```

Example: `J54JdT1AFotjmpmH` (16 chars, v5 peer)

This enables:
- Anti-spoofing via message signatures
- Nick recovery across message channels

**Anti-Replay Protection:** All private messages include `<pubkey> <signature>` fields. The signed plaintext includes `hostid` (directory onion or `onion-network` for direct) preventing replay across channels.

### Multi-part Messages

- Unencrypted messages may contain multiple commands (split on `!`)
- Used for `!reloffer` and `!absoffer` combined announcements
- **NOT allowed** for encrypted messages

### Reference Implementation Compatibility

**Orderbook Request Behavior:**
- Reference orderbook watcher requests offers once at startup
- Our implementation requests on startup + periodically
- Makers should respond to every `!orderbook` request

**Stale Offer Filtering:**
- Offers older than `max_offer_age` (default 1 hour) are filtered
- Maker disconnects are tracked for filtering

**Known Directory Servers:**

| Network | Type | Address |
|---------|------|---------|
| Mainnet | Reference | `jmarketxf5wc4aldf3slm5u6726zsky52bqnfv6qyxe5hnafgly6yuyd.onion:5222` |
| Mainnet | JM-NG | `nakamotourflxwjnjpnrk7yc2nhkf6r62ed4gdfxmmn5f4saw5q5qoyd.onion:5222` |

### Maker Selection Algorithm

After collecting offers, the taker selects makers through three phases:

**Phase 1 - Filtering**: Remove offers that don't meet criteria (amount range, fee limits, offer type, ignored makers).

**Phase 2 - Deduplication**: If a maker advertises multiple offers under the same nick, only the cheapest offer is kept. This ensures makers cannot game selection by flooding the orderbook.

**Phase 3 - Selection**: Choose `n` makers from the deduplicated list using one of these algorithms:

| Algorithm | Behavior |
|-----------|----------|
| `fidelity_bond_weighted` (default) | Mixed strategy: ~87.5% slots filled by bond-weighted selection, remaining slots randomly from all offers |
| `cheapest` | Lowest fee first |
| `weighted` | Exponentially weighted by inverse fee |
| `random` | Uniform random selection |

**Key Point**: Selection probability is proportional to the **maker identity (nick)**, not the number of offers. A maker with 5 offers has the same selection probability as a maker with 1 offer (assuming both pass filters).

**Maker Replacement on Non-Response:**

When makers fail to respond, the taker can automatically select replacements instead of aborting:

- Configuration: `max_maker_replacement_attempts` (default: 3, range: 0-10)
- Failed makers added to ignored list for the session
- New makers go through the full fill/auth flow
- If not enough replacements available, CoinJoin aborts

Implementation: `taker/src/taker/orderbook.py`

### Multi-Channel Message Deduplication

When connected to N directory servers, each message is received N times. The deduplication system prevents:
1. Processing the same protocol message multiple times (expensive operations like `!auth`, `!tx`)
2. Rate limiter counting duplicates as violations
3. Log spam from duplicate messages

**Message Fingerprinting**: Messages identified by `from_nick:command:first_arg`:
- `alice:fill:order123` - Fill request for order 123
- `bob:pubkey:abc123` - Pubkey response

**Time-Based Window**: Duplicates within a 30-second window are dropped.

**Implementation**:
- **Maker** (`maker/bot.py`): Uses `MessageDeduplicator` to filter incoming messages
- **Taker** (`taker/taker.py`): Uses `ResponseDeduplicator` in `wait_for_responses()`
- **Orderbook**: Uses `(counterparty, oid)` as key for offer deduplication

### Feature Flags System

This implementation uses feature flags instead of protocol version bumps to enable progressive capability adoption while maintaining backward compatibility.

**Why feature flags?**
1. Reference implementation only accepts `proto-ver=5` - version bumps would break interoperability
2. Features can be adopted independently without "all or nothing" upgrades
3. Peers advertise what they support; both sides negotiate per-session

**Available Features:**

| Feature | Description |
|---------|-------------|
| `extended_peerlist` | Supports extended peerlist format with feature flags in `F:` field |
| `neutrino_compat` | Supports extended UTXO format with scriptPubKey and blockheight |

**Extended Peerlist Format:**

```
nick;location;F:feature1+feature2
```

The `+` separator (not `,`) avoids ambiguity since peerlist entries are comma-separated.

**Neutrino Compatibility:**

Extended UTXO format includes scriptPubKey + block height for verification:

| Format | Example |
|--------|---------|
| Legacy | `txid:vout` |
| Extended | `txid:vout:scriptpubkey:height` |

**Handshake Integration:**

```json
{
  "proto-ver": 5,
  "features": {"extended_peerlist": true, "neutrino_compat": true}
}
```

The `features` dict is ignored by reference implementation but preserved for our peers.

---

## Privacy Mechanisms

### Mixdepths

HD path: `m/84'/0'/0'/mixdepth/chain/index` (P2WPKH Native SegWit)

**Design (Default: 5 isolated accounts):**
- Inputs for a CoinJoin come from a **single mixdepth**
- CoinJoin outputs go to the **next mixdepth** (wrapping 4 -> 0)
- Change outputs stay in the **same mixdepth**

This prevents merging CoinJoin outputs with their change, blocking trivial linkage.

**Address Branches (per mixdepth):**
- External (0): Receiving addresses
- Internal (1): Change addresses

Example:
```
mixdepth 0/external: m/84'/0'/0'/0/0/0 -> bc1q... (receive)
mixdepth 0/internal: m/84'/0'/0'/0/1/0 -> bc1q... (change)
mixdepth 1/external: m/84'/0'/0'/1/0/0 -> bc1q... (CJ output from mixdepth 0)
```

### PoDLE (Proof of Discrete Log Equivalence)

PoDLE prevents Sybil attacks by requiring takers to commit to UTXO ownership before makers reveal their UTXOs.

**The Problem:** Without PoDLE, an attacker could request CoinJoins from many makers, collect their UTXO sets, then abort - linking maker UTXOs without cost.

**Protocol Flow:**

1. **Taker commits**: $C = H(P_2)$ where $P_2 = k \cdot J$ ($J$ is NUMS point)
2. **Maker accepts**: Sends encryption pubkey
3. **Taker reveals**: Sends $P$ (pubkey), $P_2$, and Schnorr-like proof
4. **Maker verifies**: $H(P_2) = C$, proof valid, UTXO exists
5. **Maker broadcasts**: `!hp2` to blacklist commitment network-wide

The proof shows that $P = k \cdot G$ and $P_2 = k \cdot J$ use the same private key $k$ without revealing $k$.

**NUMS Point Index System:**

Each UTXO can generate multiple different commitments using different NUMS points (indices 0-9):
- Index 0: First use (preferred)
- Index 1-2: Retry after failed CoinJoins (accepted by default)
- Index 3+: Only if maker configures higher `taker_utxo_retries`

**UTXO Selection for PoDLE:**

| Criterion | Default | Rationale |
|-----------|---------|-----------|
| Min confirmations | 5 | Prevents double-spend |
| Min value | 20% of cj_amount | Economic stake |

Selection priority: confirmations (desc) -> value (desc)

**Commitment Tracking:**
- **Taker** (`cmtdata/commitments.json`): Tracks locally used commitments
- **Maker** (`cmtdata/commitmentlist`): Network-wide blacklist via `!hp2`

### Fidelity Bonds

Fidelity bonds allow makers to prove locked bitcoins, improving trust and selection probability.

**Purpose:** Makers lock bitcoin in timelocked UTXOs to gain priority in taker selection. Bond value increases with amount and time until unlock.

**Bond Address Generation:**

Fidelity bonds use P2WSH addresses with a timelock script:

```
<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
```

Generate a bond address:

```bash
jm-wallet generate-bond-address \
  --mnemonic-file wallet.enc \
  --password "your-password" \
  --locktime-date "2026-01-01" \
  --index 0
```

**Bond Registry (`fidelity_bonds.json`):**

Stores bond metadata including:
- Address, locktime, derivation path
- UTXO info (txid, vout, value, confirmations)
- Certificate fields for cold storage bonds

Commands:
- `jm-wallet registry-list` - List all bonds with status
- `jm-wallet registry-show <address>` - Show bond details
- `jm-wallet registry-sync` - Update funding status from blockchain

**Bond Proof Structure (252 bytes):**

| Field | Size | Description |
|-------|------|-------------|
| nick_sig | 72 | DER signature (padded with 0xff) |
| cert_sig | 72 | DER signature (padded with 0xff) |
| cert_pubkey | 33 | Certificate public key |
| cert_expiry | 2 | Expiry period (2016-block periods, little-endian) |
| utxo_pubkey | 33 | UTXO public key |
| txid | 32 | Transaction ID |
| vout | 4 | Output index (little-endian) |
| timelock | 4 | Locktime value (little-endian) |

**DER Signature Padding**: Signatures are padded at the start with `0xff` bytes to exactly 72 bytes. The DER header byte `0x30` makes stripping padding straightforward during verification.

**Signature Purposes**:
- **Nick signature**: Proves maker controls certificate key (signs `taker_nick|maker_nick`)
- **Certificate signature**: Binds cert key to UTXO (signs `fidelity-bond-cert|cert_pub|expiry`)

**Certificate Expiry**:
- Encoding: 2-byte unsigned integer (little-endian)
- Represents: Difficulty retarget period number (period = block_height / 2016)
- Calculation: `cert_expiry = ((current_block + 2) // 2016) + 1`
- Validation: Invalid if `current_block_height > cert_expiry * 2016`

**Certificate Chain:**

```
UTXO keypair (cold) -> signs -> certificate (hot) -> signs -> nick proofs
```

Allows cold storage of bond private key while hot wallet handles per-session proofs.

**Cold Wallet Setup:**

For maximum security, keep the bond UTXO private key on a hardware wallet:

1. Get public key from hardware wallet (Sparrow)
2. Create bond address: `jm-wallet create-bond-address <pubkey> --locktime-date "2026-01"`
3. Fund the bond address
4. Generate hot keypair: `jm-wallet generate-hot-keypair --bond-address <addr>`
5. Prepare certificate message: `jm-wallet prepare-certificate-message <addr>`
6. Sign message in Sparrow (Standard/Electrum format, NOT BIP322)
7. Import certificate: `jm-wallet import-certificate <addr> --cert-signature '<sig>' --cert-expiry <period>`
8. Run maker - certificate used automatically

**Spending Bonds:**

After locktime expires:

```bash
jm-wallet send <destination> --mixdepth 0 --amount 0  # Sweep
```

The wallet automatically handles P2WSH witness construction and nLockTime.

**Note:** P2WSH fidelity bond UTXOs cannot be used in CoinJoins.

### Cryptographic Foundations

**Introductory Video**: For a visual introduction to elliptic curves and how they work in Bitcoin, watch [Curves which make Bitcoin possible](https://www.youtube.com/watch?v=qCafMW4OG7s) by MetaMaths.

**secp256k1 Elliptic Curve:**

JoinMarket uses the secp256k1 elliptic curve, the same curve used by Bitcoin. The curve is defined by:

$$y^2 = x^3 + 7 \pmod{p}$$

Where:
- Field prime: `p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1`
- In hex: `p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
- Group order: `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- All arithmetic modulo `n` for scalars, modulo `p` for field elements

**Reference**: [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf), Section 2.4.1

**Generator Point G:**

The generator point G is a specific point on secp256k1 with known coordinates. All Bitcoin and JoinMarket public keys are derived as scalar multiples of G.

Coordinates (from SEC 2 v2.0 Section 2.4.1):
```
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

Compressed form (33 bytes): `0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798`

**NUMS Points:**

NUMS (Nothing Up My Sleeve) points are alternative generator points $J_0, J_1, \ldots, J_{255}$ that have no known discrete logarithm relationship to $G$. This property is crucial - if someone knew $k$ such that $J_i = k \cdot G$, they could forge PoDLE proofs.

The NUMS points are generated deterministically from G using a transparent algorithm that leaves no room for hidden backdoors. Anyone can verify the generation process.

**Generation Algorithm:**

```
for G in [G_compressed, G_uncompressed]:
    seed = G || i (as single byte)
    for counter in [0, 1, ..., 255]:
        seed_c = seed || counter (as single byte)
        x = SHA256(seed_c)
        point = 0x02 || x  (compressed point with even y)
        if point is valid on curve:
            return point
```

Python implementation:

```python
def generate_nums_point(index: int) -> Point:
    for G in [G_COMPRESSED, G_UNCOMPRESSED]:
        seed = G + bytes([index])
        for counter in range(256):
            seed_c = seed + bytes([counter])
            x = sha256(seed_c)
            claimed_point = b'\x02' + x
            if is_valid_curve_point(claimed_point):
                return claimed_point
```

**Reference**: [PoDLE Specification](https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8) by Adam Gibson (waxwing)

Test vectors (from joinmarket-clientserver):

| Index | NUMS Point (hex) |
|------:|:-----------------|
| 0 | `0296f47ec8e6d6a9c3379c2ce983a6752bcfa88d46f2a6ffe0dd12c9ae76d01a1f` |
| 1 | `023f9976b86d3f1426638da600348d96dc1f1eb0bd5614cc50db9e9a067c0464a2` |
| 5 | `02bbc5c4393395a38446e2bd4d638b7bfd864afb5ffaf4bed4caf797df0e657434` |
| 9 | `021b739f21b981c2dcbaf9af4d89223a282939a92aee079e94a46c273759e5b42e` |
| 100 | `02aacc3145d04972d0527c4458629d328219feda92bef6ef6025878e3a252e105a` |
| 255 | `02a0a8694820c794852110e5939a2c03f8482f81ed57396042c6b34557f6eb430a` |

**Implementation**: `jmcore/src/jmcore/podle.py`

### PoDLE Mathematics

The PoDLE proves that two public keys $P = k \cdot G$ and $P_2 = k \cdot J$ share the same private key $k$:

1. **Commitment**: Taker computes $C = \textrm{SHA256}(P_2)$ and sends to maker

2. **Revelation**: After maker commits, taker reveals $(P, P_2, s, e)$ where:
   - $K_G = r \cdot G$, $K_J = r \cdot J$ (commitments using random nonce $r$)
   - $e = \textrm{SHA256}(K_G \| K_J \| P \| P_2)$ (challenge hash)
   - $s = r + e \cdot k \pmod{n}$ (Schnorr-like response)

3. **Verification**: Maker checks:
   - $\textrm{SHA256}(P_2) \stackrel{?}{=} C$ (commitment opens correctly)
   - $e \stackrel{?}{=} \textrm{SHA256}((s \cdot G - e \cdot P) \| (s \cdot J - e \cdot P_2) \| P \| P_2)$

This ensures the taker controls a real UTXO without revealing which one until makers have committed, preventing costless Sybil attacks on the orderbook.

---

## Wallet

### HD Structure

HD path: `m/84'/0'/0'/mixdepth/chain/index` (BIP84 P2WPKH)

- **Mixdepths**: 5 isolated accounts (0-4)
- **Chains**: External (0) for receiving, Internal (1) for change
- **Index**: Sequential address index

### BIP39 Passphrase Support

JoinMarket NG supports the optional BIP39 passphrase ("25th word"):

**Important Distinction:**
- **File encryption password** (`--password`): Encrypts mnemonic file with AES
- **BIP39 passphrase** (`--bip39-passphrase`): Used in seed derivation per BIP39

The passphrase is provided when **using** the wallet, not when importing:

```bash
# Import only stores mnemonic (no passphrase)
jm-wallet import --words 24

# Passphrase provided at usage time:
jm-wallet info --prompt-bip39-passphrase
jm-wallet info --bip39-passphrase "my phrase"
BIP39_PASSPHRASE="my phrase" jm-wallet info
```

**Security Notes:**
- Empty passphrase (`""`) is valid and different from no passphrase
- Passphrase is case-sensitive and whitespace-sensitive
- **Not read from config file** to prevent accidental exposure

### UTXO Selection

**Taker Selection:**
- **Normal**: Minimum UTXOs to cover `cj_amount + fees`
- **Sweep** (`--amount=0`): All UTXOs, zero change (best privacy)

```bash
jm-taker coinjoin --amount=0 --mixdepth=0 --destination=INTERNAL
```

**Maker Merge Algorithms:**

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

### Backend Systems

**Descriptor Wallet Backend (Recommended):**
- Method: `importdescriptors` + `listunspent` RPC
- Requirements: Bitcoin Core v24+
- Storage: ~900 GB + small wallet file
- Sync: Fast after initial descriptor import
- **Smart Scan**: Scans ~1 year of blocks initially, full rescan in background

Trade-off: Addresses stored in Core wallet file - never use with third-party node.

**Bitcoin Core Backend (Legacy):**
- Method: `scantxoutset` RPC (no wallet required)
- Requirements: Bitcoin Core v30+
- Sync: Slow (~90s per scan on mainnet)

Useful for one-off operations without persistent tracking.

**Neutrino Backend:**
- Method: BIP157/158 compact block filters
- Requirements: [neutrino-api server](https://github.com/m0wer/neutrino-api)
- Storage: ~500 MB
- Sync: Minutes instead of days

**Decision Matrix:**
- Use DescriptorWallet if: You run a full node (recommended)
- Use BitcoinCore if: Simple one-off UTXO queries
- Use Neutrino if: Limited storage, fast setup needed

**Neutrino Broadcast Strategy:**

Neutrino cannot access the mempool, affecting transaction verification:

| Policy | Behavior |
|--------|----------|
| `SELF` | Broadcast via own backend (always verifiable) |
| `RANDOM_PEER` | Try makers sequentially, fall back to self |
| `MULTIPLE_PEERS` | Broadcast to N makers simultaneously (default) |
| `NOT_SELF` | Try makers only, no fallback |

Confirmation monitoring uses block-based UTXO lookups.

### Periodic Wallet Rescan

Both maker and taker support periodic rescanning:

| Setting | Default | Description |
|---------|---------|-------------|
| `rescan_interval_sec` | 600 | How often to rescan |
| `post_coinjoin_rescan_delay` | 60 | Delay after CoinJoin (maker) |

**Maker:** After CoinJoin, rescans to detect balance changes and update offers automatically.

**Taker:** Rescans between schedule entries to track pending confirmations.

---

## Configuration

### Config File

JoinMarket NG uses TOML configuration at `~/.joinmarket-ng/config.toml`.

**Priority (highest to lowest):**
1. CLI arguments
2. Environment variables
3. Config file
4. Built-in defaults

**Auto-Generation:** On first run, config is created with all settings commented out, showing defaults.

**Environment Variable Mapping:**

| Config File | Environment Variable |
|-------------|---------------------|
| `[tor]` `socks_host` | `TOR__SOCKS_HOST` |
| `[bitcoin]` `rpc_url` | `BITCOIN__RPC_URL` |
| `[maker]` `min_size` | `MAKER__MIN_SIZE` |

**Configuration Sections:**

| Section | Description |
|---------|-------------|
| `[tor]` | SOCKS proxy and control port |
| `[bitcoin]` | Backend settings (RPC, Neutrino) |
| `[network]` | Protocol network, directory servers |
| `[wallet]` | HD wallet structure |
| `[notifications]` | Push notification settings |
| `[logging]` | Log level and options |
| `[maker]` | Maker-specific settings |
| `[taker]` | Taker-specific settings |

**Example:**

```toml
[tor]
socks_host = "127.0.0.1"
socks_port = 9050

[bitcoin]
backend_type = "descriptor_wallet"
rpc_url = "http://127.0.0.1:8332"
rpc_user = "jm"
rpc_password = "secret"

[network]
network = "mainnet"

[maker]
min_size = 50000
cj_fee_relative = "0.002"
merge_algorithm = "gradual"
```

### Tor Integration

All components use Tor for privacy:

| Component | SOCKS Proxy | Hidden Service |
|-----------|-------------|----------------|
| Directory Server | No | Permanent |
| Maker | Yes | Ephemeral (recommended) |
| Taker | Yes | No |
| Orderbook Watcher | Yes | No |

**Directory Server:** Requires permanent hidden service in torrc:

```
HiddenServiceDir /var/lib/tor/directory_hs
HiddenServiceVersion 3
HiddenServicePort 5222 127.0.0.1:5222
```

**Maker:** Uses SOCKS proxy for outgoing + ephemeral hidden service via control port:

```bash
jm-maker start \
  --socks-host=127.0.0.1 --socks-port=9050 \
  --tor-control-enabled \
  --tor-control-host=127.0.0.1 --tor-control-port=9051
```

Creates fresh `.onion` each session for better privacy.

**Taker/Orderbook:** SOCKS proxy only for outgoing connections.

### Notifications

Push notifications via [Apprise](https://github.com/caronc/apprise) supporting 100+ services.

**Configuration:**

```toml
[notifications]
urls = ["gotify://your-server.com/token", "tgram://bot/chat"]
include_amounts = true
include_txids = false  # Privacy risk
use_tor = true
```

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `NOTIFICATIONS__URLS` | JSON array of Apprise URLs |
| `NOTIFICATIONS__INCLUDE_AMOUNTS` | Include satoshi amounts |
| `NOTIFICATIONS__INCLUDE_TXIDS` | Include transaction IDs |
| `NOTIFICATIONS__USE_TOR` | Route through Tor |

**Per-event toggles:** `notify_fill`, `notify_signing`, `notify_confirmed`, etc.

**Example URLs:**

```bash
# Gotify
export NOTIFICATIONS__URLS='["gotify://host/token"]'

# Telegram
export NOTIFICATIONS__URLS='["tgram://bot_token/chat_id"]'

# Multiple services
export NOTIFICATIONS__URLS='["gotify://host/token", "tgram://bot/chat"]'
```

### Transaction Policies

**Dust Threshold:**

Default: 27,300 satoshis (reference implementation compatible)

This is higher than Bitcoin Core's relay dust (546 sats for P2WPKH) to avoid creating outputs that may be expensive to spend relative to their value.

| Scenario | Threshold |
|----------|-----------|
| Change output < threshold | Donated to fees |
| CoinJoin output < threshold | Transaction rejected |

**Minimum Relay Fee:**

Bitcoin Core default: 1.0 sat/vB

For sub-satoshi fee rates, configure `minrelaytxfee` in `bitcoin.conf`:

```ini
minrelaytxfee=0.0000001  # 0.1 sat/vB
```

**Bitcoin Amount Handling:**

All amounts are **integer satoshis** internally. Do not use float or Decimal.

---

## Security

### Threat Model

- **Attackers**: Malicious peers, network observers, malicious directory operators
- **Assets**: Peer privacy, network availability, user funds
- **Threats**: DDoS, privacy leaks, message tampering, eclipse attacks

### Directory Server Security

Directory servers are similar to Bitcoin DNS seeds - required for peer discovery, not message routing. However, they represent security-relevant infrastructure.

**Threats:**

| Threat | Mitigation |
|--------|------------|
| Eclipse Attack | Multi-directory fallback, peer diversity |
| Selective Censorship | Ephemeral nicks, multiple directories |
| Metadata Correlation | Tor connections, ephemeral nicks |
| DoS | Rate limiting, connection limits |

**Multi-Directory Strategy:** Connect to multiple independent directories, merge peer lists, prefer direct P2P connections.

### Message Security

**Rate Limiting (Directory Server):**

| Setting | Default | Description |
|---------|---------|-------------|
| `message_rate_limit` | 100/s | Sustained rate |
| `message_burst_limit` | 200 | Burst size |
| `max_message_size` | 2MB | Maximum message size |
| `max_line_length` | 64KB | Maximum JSON-line length |
| `max_json_nesting_depth` | 10 | Maximum nesting |

**Validation Flow:**
```
Raw Message -> Line Length Check -> JSON Parse -> Nesting Check -> Model
```

**Encryption:**

| Command | Encrypted | Notes |
|---------|-----------|-------|
| `!pubkey` | No | Initial key exchange |
| `!fill`, `!auth`, `!ioauth`, `!tx`, `!sig` | Yes (NaCl) | CoinJoin negotiation |
| `!push` | No | Transaction already public |

**Channel Consistency:** All messages in a CoinJoin session must use the same channel (direct or relay). Prevents session confusion attacks.

### Neutrino Security

Additional protections for light clients:

| Protection | Default | Description |
|------------|---------|-------------|
| `max_watched_addresses` | 10,000 | Prevents memory exhaustion |
| `max_rescan_depth` | 100,000 | Limits expensive rescans |
| Blockheight validation | SegWit activation | Rejects old heights |

**Privacy Note:** Third-party neutrino-api servers can observe query patterns. Run locally behind Tor.

### Maker DoS Defense

**Layer 1: Tor PoW Defense (Tor 0.4.9.2+)**

Clients solve computational puzzles before establishing circuits:

| Setting | Default |
|---------|---------|
| `pow_enabled` | true |
| `pow_queue_rate` | 25/s |
| `pow_queue_burst` | 200 |

Difficulty auto-adjusts based on load.

**Layer 2: Application Rate Limiting**

Per-connection limits on `!orderbook` requests:

| Setting | Default |
|---------|---------|
| `orderbook_interval` | 30s |
| `orderbook_ban_threshold` | 10 violations |
| `ban_duration` | 3600s |

### Transaction Verification

The `verify_unsigned_transaction()` function performs critical checks before signing:

1. **Input Inclusion**: All maker UTXOs present in inputs
2. **CoinJoin Output**: Exactly one output >= amount to maker's CJ address
3. **Change Output**: Exactly one output >= expected to maker's change address
4. **Positive Profit**: `cjfee - txfee > 0` (maker never pays to participate)
5. **No Duplicate Outputs**: CJ and change addresses appear exactly once
6. **Well-formed**: Parseable, valid structure

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| DDoS | Tor PoW, rate limiting, connection limits |
| Sybil | Fidelity bonds, PoDLE |
| Replay | Session-bound state, ephemeral keys |
| MitM | End-to-end NaCl encryption |
| Rescan Abuse | Blockheight validation, depth limits |

### Critical Security Code

| Module | Purpose | Coverage |
|--------|---------|----------|
| `maker/tx_verification.py` | CoinJoin verification | 100% |
| `jmwallet/wallet/signing.py` | Transaction signing | 95% |
| `jmcore/podle.py` | Anti-sybil proof | 90%+ |
| `directory_server/rate_limiter.py` | DoS prevention | 100% |

---

## Development

### Dependency Management

Using [pip-tools](https://github.com/jazzband/pip-tools) for pinned dependencies:

```bash
pip install pip-tools

# Update pinned dependencies
cd jmcore
python -m piptools compile -Uv pyproject.toml -o requirements.txt
```

Install order: `jmcore` -> `jmwallet` -> other packages

### Running Tests

```bash
# Unit tests with coverage
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests

# E2E tests (requires Docker)
./scripts/run_all_tests.sh
```

Test markers:
- Default: `-m "not docker"` excludes Docker tests
- `e2e`: Our maker/taker implementation
- `reference`: JAM compatibility tests
- `neutrino`: Light client tests

### Reproducible Builds

Docker images are built reproducibly using `SOURCE_DATE_EPOCH` to ensure identical builds from the same source code. This allows independent verification that released binaries match the source.

**How it works:**

- `SOURCE_DATE_EPOCH` is set to the git commit timestamp
- All platforms (amd64, arm64, armv7) are built with the same timestamp
- Per-platform layer digests are stored in the release manifest
- Verification compares layer digests (not manifest digests) for reliability

**Why layer digests?**

Docker manifest digests vary based on manifest format (Docker distribution vs OCI) even for identical image content. CI pushes to a registry using Docker format, while local builds typically use OCI format. Layer digests are content-addressable hashes of the actual tar.gz layer content and are identical regardless of manifest format, making them reliable for reproducibility verification.

**Verify a release:**

```bash
# Check GPG signatures and published image digests
./scripts/verify-release.sh 1.0.0

# Full verification: signatures + published digests + reproduce build locally
./scripts/verify-release.sh 1.0.0 --reproduce

# Require multiple signatures
./scripts/verify-release.sh 1.0.0 --min-sigs 2
```

The `--reproduce` flag builds the Docker image for your current architecture and compares layer digests against the release manifest. This verifies the released image content matches the source code.

**Sign a release:**

```bash
# Verify + reproduce build + sign (--reproduce is enabled by default)
./scripts/sign-release.sh 1.0.0 --key YOUR_GPG_KEY

# Skip reproduce check (not recommended)
./scripts/sign-release.sh 1.0.0 --key YOUR_GPG_KEY --no-reproduce
```

All signers should use `--reproduce` to verify builds are reproducible before signing. Multiple signatures only add value if each signer independently verifies reproducibility.

**Build locally (manual):**

```bash
VERSION=1.0.0
git checkout $VERSION
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

# Build for your architecture as OCI tar
docker buildx build \
  --file ./maker/Dockerfile \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --platform linux/amd64 \
  --output type=oci,dest=maker.tar \
  .

# Extract layer digests from OCI tar
mkdir -p oci && tar -xf maker.tar -C oci
manifest_digest=$(jq -r '.manifests[0].digest' oci/index.json)
jq -r '.layers[].digest' "oci/blobs/sha256/${manifest_digest#sha256:}" | sort
```

**Release manifest format:**

The release manifest (`release-manifest-<version>.txt`) contains:

```
commit: <git-sha>
source_date_epoch: <timestamp>

## Docker Images
maker-manifest: sha256:...    # Registry manifest list digest
taker-manifest: sha256:...

## Per-Platform Layer Digests (for reproducibility verification)

### maker-amd64-layers
sha256:abc123...
sha256:def456...

### maker-arm64-layers
sha256:abc123...
sha256:ghi789...
```

Signatures are stored in `signatures/<version>/<fingerprint>.sig`.

### Troubleshooting

**Wallet Sync Issues:**

```bash
# List wallets
bitcoin-cli listwallets

# Check balance
bitcoin-cli -rpcwallet="jm_xxx_mainnet" getbalance

# Manual rescan
bitcoin-cli -rpcwallet="jm_xxx_mainnet" rescanblockchain 900000

# Check progress
bitcoin-cli -rpcwallet="jm_xxx_mainnet" getwalletinfo
```

| Symptom | Cause | Solution |
|---------|-------|----------|
| First sync times out | Initial descriptor import | Wait and retry |
| Second sync hangs | Concurrent rescan running | Check getwalletinfo |
| Missing transactions | Scan started too late | rescanblockchain earlier |
| Wrong balance | BIP39 passphrase mismatch | Verify passphrase |

**Smart Scan Configuration:**

```toml
[wallet]
scan_lookback_blocks = 12960  # ~3 months
# Or explicit start:
scan_start_height = 870000
```

**RPC Timeout:**

1. Check Core is synced: `bitcoin-cli getblockchaininfo`
2. Increase timeout: `rpcservertimeout=120` in bitcoin.conf
3. First scan may take minutes - retry after completion

---

## Best Practices

*This section will contain privacy tips and best practices for users of all technical levels.*

**Coming soon:**
- Recommended number of CoinJoin rounds
- Optimal mixdepth usage patterns
- When to use sweep mode
- Timing considerations
- UTXO management strategies
- Fidelity bond recommendations for makers

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
