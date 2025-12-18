# JoinMarket Protocol Documentation

This document consolidates the JoinMarket protocol specification, implementation details, architecture, and testing guide for the modern Python refactored implementation.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Design Principles](#design-principles)
4. [Component Architecture](#component-architecture)
5. [Wallet Design](#wallet-design)
6. [Neutrino Light Client](#neutrino-light-client)
7. [Messaging Protocol](#messaging-protocol)
8. [CoinJoin Protocol Flow](#coinjoin-protocol-flow)
9. [Encryption Protocol](#encryption-protocol)
10. [PoDLE (Proof of Discrete Log Equivalence)](#podle-proof-of-discrete-log-equivalence)
11. [Fidelity Bonds](#fidelity-bonds)
12. [Transaction Types](#transaction-types)
13. [Offer System](#offer-system)
14. [Technology Stack](#technology-stack)
15. [Performance Characteristics](#performance-characteristics)
16. [Security Model](#security-model)
17. [Testing Strategy](#testing-strategy)
18. [Testing Guide](#testing-guide)
19. [Protocol Implementation Details](#protocol-implementation-details)

---

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
| `neutrino_server` | Lightweight SPV server (BIP157/158) |

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
│                         JoinMarket System                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      Directory Server                            │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │    │
│  │  │  Connection  │  │    Peer      │  │   Message    │           │    │
│  │  │   Manager    │──│  Registry    │──│    Router    │           │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                            ▲                                             │
│                            │ connects                                    │
│         ┌──────────────────┼──────────────────┐                         │
│         │                  │                  │                          │
│         ▼                  ▼                  ▼                          │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐                  │
│  │   Maker     │   │  Orderbook   │   │   Taker      │                  │
│  │    Bot      │   │   Watcher    │   │    Bot       │                  │
│  └─────────────┘   └──────────────┘   └──────────────┘                  │
│         │                                     │                          │
│         │                                     │                          │
│         ▼                                     ▼                          │
│  ┌─────────────────────────────────────────────────┐                    │
│  │                    jmwallet                      │                    │
│  │  ┌──────────────┐  ┌──────────────┐             │                    │
│  │  │  BIP32/39/84 │  │   Backends   │             │                    │
│  │  │    Wallet    │  │ (Core, SPV)  │             │                    │
│  │  └──────────────┘  └──────────────┘             │                    │
│  └─────────────────────────────────────────────────┘                    │
│                            │                                             │
│                            │ uses                                        │
│                            ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                          jmcore                                  │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │    │
│  │  │   Protocol   │  │    Models    │  │    Crypto    │           │    │
│  │  │   Messages   │  │  (Pydantic)  │  │  Primitives  │           │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │    │
│  │  ┌──────────────┐  ┌──────────────┐                             │    │
│  │  │   Network    │  │    Bond      │                             │    │
│  │  │  Primitives  │  │    Calc      │                             │    │
│  │  └──────────────┘  └──────────────┘                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
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

---

## Neutrino Light Client

Neutrino is a BIP157/BIP158 light client that provides privacy-preserving blockchain access without requiring a full Bitcoin node.

### Why Neutrino?

| Feature | Full Node | Traditional SPV | Neutrino SPV |
|---------|-----------|----------------|--------------|
| Storage | ~500 GB | ~50 MB | ~500 MB |
| Initial Sync | Days | Minutes | Minutes |
| Privacy | Full | Low (reveals addresses) | High (downloads filters) |
| Validation | Full | Headers only | Headers + filters |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Neutrino Server (Go)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   P2P Node   │    │   Filter     │    │   REST API   │       │
│  │  (btcsuite)  │────│    Store     │────│   Handler    │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                                        │               │
│         │  BIP157/158                           │ HTTP          │
│         ▼                                        ▼               │
│  ┌──────────────┐                        ┌──────────────┐       │
│  │   Bitcoin    │                        │   Python     │       │
│  │   Network    │                        │   Backend    │       │
│  └──────────────┘                        └──────────────┘       │
│                                                                  │
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
# Start Neutrino server (standalone)
docker-compose --profile neutrino up -d neutrino

# Or with full system
docker-compose --profile neutrino up -d
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

- `from_nick`: Sender's nickname (e.g., `J5AiXEVUkwBBZs8A`)
- `to_nick`: Recipient or `PUBLIC` for broadcasts
- `command`: Command with `!` prefix
- `arguments`: Space-separated arguments

### Nick Format

Nicks are derived from ephemeral keypairs:

```
J + version + base58(sha256(pubkey)[:10]) + padding
```

Example: `J54JdT1AFotjmpmH` (16 chars total)

The nick format enables:
1. Anti-spoofing via message signatures
2. Nick recovery across multiple message channels

---

## CoinJoin Protocol Flow

### Phase 1: Orderbook Discovery

```
Taker                          Directory                        Maker
  |                                |                               |
  |--- PUBMSG !orderbook --------->|                               |
  |                                |--- Broadcast ----------------->|
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
4. Broadcasts to the Bitcoin network

### Implementation Reference

The protocol flow is implemented in:
- `taker/src/taker/taker.py:292-449` - `do_coinjoin()` method
- `maker/src/maker/bot.py:265-377` - Message handlers
- `maker/src/maker/coinjoin.py` - CoinJoin session state machine

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

### NUMS Point Generation

NUMS points are precomputed for indices 0-9:
```python
NUMS[i] = hash_to_curve(sha256("joinmarket" + str(i)))
```

Lower indices are preferred as they indicate the UTXO hasn't been used for many failed CoinJoins.

### Implementation Reference

```python
# jmcore/src/jmcore/podle.py

def generate_podle(private_key_bytes, utxo_str, index=0) -> PoDLECommitment:
    """Generate PoDLE commitment for a UTXO."""

def verify_podle(p, p2, sig, e, commitment, index_range) -> tuple[bool, str]:
    """Verify PoDLE proof."""
```

---

## Fidelity Bonds

Fidelity bonds allow makers to prove they have locked bitcoins, improving trust and selection probability.

### Bond Proof Structure

```
nick_sig + cert_sig + cert_pubkey + cert_expiry + utxo_pubkey + txid + vout + timelock
72       + 72       + 33          + 2           + 33          + 32   + 4    + 4 = 252 bytes
```

### Certificate Chain

```
Fidelity bond keypair ----signs----> certificate ----signs----> IRC nicknames
```

The two-signature scheme allows:
1. Cold storage of the fidelity bond private key
2. Hot wallet holds only the certificate keypair
3. Certificate expiry limits exposure if hot wallet is compromised

### Bond Value Calculation

Bond value depends on:
- Amount of locked bitcoin
- Time until unlock (longer = more valuable)
- Current confirmation count

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

## Technology Stack

### Core Technologies

- **Python 3.14+**: Modern Python with type hints
- **Go**: Neutrino server implementation
- **AsyncIO**: High-performance async networking
- **Pydantic**: Type-safe data validation
- **Loguru**: Structured logging

### Development Tools

- **Ruff**: Fast linting and formatting
- **MyPy**: Static type checking
- **Pytest**: Testing framework
- **Pre-commit**: Git hooks for quality

### Infrastructure

- **Docker**: Containerization
- **Tor**: Onion service privacy
- **Systemd**: Service management (production)

---

## Performance Characteristics

### Latency

- **Handshake**: < 100ms (local), < 500ms (over Tor)
- **Message routing**: < 10ms (local), < 100ms (over Tor)
- **Peer lookup**: O(1) with dict-based registry

### Throughput

- **Connections**: 1000+ concurrent (tested)
- **Messages**: 10,000+ msg/sec (local)
- **Bandwidth**: Limited by Tor (~1 MB/s typical)

### Memory

- **Base usage**: ~50 MB
- **Per peer**: ~5 KB
- **1000 peers**: ~55 MB total

### Scalability

- Horizontal: Multiple directory servers (independent)
- Vertical: Single server handles 1000+ peers
- Bottleneck: Tor network, not implementation

---

## Security Model

### Threat Model

- **Attackers**: Malicious peers, network observers
- **Assets**: Peer privacy, network availability
- **Threats**: DDoS, privacy leaks, message tampering

### Defenses

1. **Privacy**: Tor-only connections
2. **Rate Limiting**: Per-peer message limits
3. **Validation**: Protocol enforcement
4. **Network Segregation**: Mainnet/testnet isolation
5. **Authentication**: Handshake protocol

### Attack Mitigations

- **DDoS**: Connection limits, rate limiting
- **Sybil**: Fidelity bonds (future), resource limits
- **Replay**: Message timestamps (future)
- **MitM**: End-to-end encryption (JM protocol)

### Critical Security Code

The following modules are security-critical and have been designed to prevent loss of funds:

| Module | Purpose | Test Coverage |
|--------|---------|---------------|
| `maker/tx_verification.py` | Verifies CoinJoin transactions before signing | 100% |
| `jmwallet/wallet/signing.py` | Transaction signing | 95% |
| `jmcore/podle.py` | Anti-sybil proof verification | 90%+ |

---

## Testing Strategy

### Unit Tests

- All core components
- Mock external dependencies
- Test edge cases and errors
- 80%+ coverage target

### Integration Tests

- Component interactions
- Real connections (localhost)
- Error propagation
- Network scenarios

### Performance Tests

- Load testing
- Memory profiling
- Latency benchmarks (future)

---

## Testing Guide

### Prerequisites

- Docker and Docker Compose
- Python 3.14+ with project dependencies
- Bitcoin Core regtest via Docker

### Setup

```bash
# Start infrastructure
docker compose up -d bitcoin directory-server

# Verify
docker ps
```

### Test Wallets

**Maker 1**
- Mnemonic: `avoid whisper mesh corn already blur sudden fine planet chicken hover sniff`
- CJ fee: 0.03%

**Maker 2**
- Mnemonic: `minute faint grape plate stock mercy tent world space opera apple rocket`
- CJ fee: 0.025%

**Taker**
- Mnemonic: `burden notable love elephant orbit couch message galaxy elevator exile drop toilet`

### Running a Test CoinJoin

1. **Start makers**:
```bash
PYTHONPATH="jmcore/src:jmwallet/src:maker/src" python3 -m maker.cli start \
  --mnemonic "avoid whisper..." \
  --network regtest \
  --directory-servers 127.0.0.1:5222
```

2. **Run taker**:
```bash
PYTHONPATH="jmcore/src:jmwallet/src:taker/src" python3 -m taker.cli coinjoin \
  --mnemonic "burden notable..." \
  --network regtest \
  --amount 50000000 \
  --counterparties 2
```

3. **Expected output**:
```
14:00:19 | INFO | Starting CoinJoin: 50000000 sats -> INTERNAL
14:00:29 | INFO | Fetched 2 offers and 0 fidelity bonds
14:00:29 | INFO | Selected 2 makers, total fee: 27,500 sats
14:00:29 | INFO | Phase 1: Sending !fill to makers...
14:00:34 | INFO | Phase 2: Sending !auth and receiving !ioauth...
14:00:39 | INFO | Phase 3: Building transaction...
14:00:44 | INFO | Phase 4: Collecting signatures...
14:00:44 | INFO | Phase 5: Broadcasting transaction...
14:00:44 | INFO | CoinJoin COMPLETE! txid: <txid>
```

### Verifying the Transaction

```bash
bitcoin-cli -regtest getrawtransaction <txid> true
```

Expected structure:
- **3 inputs**: 1 from taker + 2 from makers
- **6 outputs**: 3 equal CoinJoin outputs + 3 change outputs

### Common Issues

1. **"Peerlist empty"**: Normal for NOT-SERVING-ONION mode
2. **Signature verification failed**: Check scriptCode format (25 bytes, no length prefix)
3. **Input index mismatch**: Use input_index_map for shuffled transactions

---

## Key Files

| File | Purpose |
|------|---------|
| `jmcore/src/jmcore/protocol.py` | Protocol constants and message types |
| `jmcore/src/jmcore/crypto.py` | Cryptographic primitives, nick generation, ECDSA signing |
| `jmcore/src/jmcore/podle.py` | PoDLE generation and verification |
| `maker/src/maker/bot.py` | Maker message handling and protocol state |
| `maker/src/maker/coinjoin.py` | Maker CoinJoin session and transaction signing |
| `maker/src/maker/encryption.py` | NaCl encryption session management |
| `taker/src/taker/taker.py` | Taker CoinJoin orchestration |
| `taker/src/taker/tx_builder.py` | Transaction construction |
| `jmwallet/src/jmwallet/wallet/signing.py` | P2WPKH signing utilities |
| `neutrino_server/cmd/neutrinod/main.go` | Neutrino server entry point |
| `jmwallet/src/jmwallet/backends/neutrino.py` | Neutrino backend client |

---

## Protocol Implementation Details

This section documents the exact protocol details discovered through E2E testing with the reference JoinMarket (JAM) implementation.

### Message Signing and Verification

All JoinMarket messages are signed to prevent spoofing. The signature format is:

```
<message_content> <signing_pubkey_hex> <signature_base64>
```

**Critical**: The signature is computed over `message_content + hostid`, NOT the full message with command. The `hostid` is currently hardcoded to `1` in JoinMarket.

```python
# Correct signing (maker side)
data_to_sign = msg_content + hostid  # e.g., "nacl_pubkey_hex" + "1"
signature = nick_identity.sign_message(msg_content, hostid)
```

### NaCl Encryption Setup

The encryption uses NaCl (libsodium) Box for authenticated encryption:

1. **Key Exchange**: Each party generates an ephemeral Curve25519 keypair
2. **Fill Message**: Taker sends their NaCl pubkey in `!fill`
3. **Pubkey Response**: Maker sends their NaCl pubkey in `!pubkey`
4. **Box Creation**: Both derive shared secret via ECDH

```python
# Create NaCl Box for encryption
from nacl.public import PrivateKey, PublicKey, Box

our_private = PrivateKey.generate()
our_public = our_private.public_key
their_public = PublicKey(bytes.fromhex(counterparty_pubkey_hex))
box = Box(our_private, their_public)

# Encrypt
encrypted = box.encrypt(plaintext.encode())
encrypted_b64 = base64.b64encode(encrypted).decode()

# Decrypt
encrypted_bytes = base64.b64decode(encrypted_b64)
decrypted = box.decrypt(encrypted_bytes).decode()
```

### Auth Message Format

The `!auth` message contains the PoDLE revelation, encrypted:

**Plaintext format** (pipe-separated):
```
txid:vout|P_hex|P2_hex|sig_hex|e_hex
```

Example:
```
abc123def456...:0|03a1b2c3...|02d4e5f6...|1234abcd...|5678efgh...
```

The taker encrypts this with the maker's NaCl pubkey and sends it.

### ioauth Message Format

The `!ioauth` message from maker to taker contains:

**Plaintext format** (space-separated):
```
utxo_list auth_pub cj_addr change_addr btc_sig
```

Where:
- `utxo_list`: Comma-separated list of `txid:vout` pairs (or single utxo)
- `auth_pub`: EC public key (hex) from one of the maker's UTXOs
- `cj_addr`: Maker's CoinJoin output address
- `change_addr`: Maker's change output address
- `btc_sig`: ECDSA signature (base64) of the maker's NaCl pubkey

**Critical**: The `btc_sig` is the maker signing **their own NaCl pubkey** (not the taker's!):

```python
# Maker signs their own NaCl pubkey to prove UTXO ownership
our_nacl_pk_hex = our_nacl_public_key.encode().hex()
btc_sig = ecdsa_sign(our_nacl_pk_hex, auth_hd_key.get_private_key_bytes())
```

This binds the encryption channel to a Bitcoin key the maker controls.

### PoDLE Schnorr Signature Convention

The PoDLE uses a specific Schnorr signature variant:

**Generation** (reference implementation convention):
```python
# Generate random nonce k
k = random_scalar()

# Compute commitments
Kg = k * G
Kj = k * J  # J is the NUMS point

# Compute challenge
e = sha256(Kg || Kj || P || P2)

# Compute signature (ADDITION, not subtraction!)
s = (k + e * private_key) % N
```

**Verification**:
```python
# Verify: Kg = s*G - e*P (SUBTRACTION!)
sG = s * G
minus_e = (-e) % N
minus_eP = minus_e * P
Kg_check = sG + minus_eP  # = s*G - e*P

# Similarly for Kj
minus_eP2 = minus_e * P2
Kj_check = s*J + minus_eP2  # = s*J - e*P2

# Verify challenge
e_check = sha256(Kg_check || Kj_check || P || P2)
assert e_check == e
```

**Key insight**: The formula is `s = k + e*x` with verification `Kg = s*G - e*P`. This is opposite to some Schnorr variants that use `s = k - e*x` with `Kg = s*G + e*P`.

### ECDSA Bitcoin Message Signing

For `btc_sig` in `!ioauth`, use Bitcoin's message signing format:

```python
def ecdsa_sign(message: str, private_key_bytes: bytes) -> str:
    """Sign message using Bitcoin message format."""
    # Bitcoin message format: double SHA256 with prefix
    prefix = b"\x18Bitcoin Signed Message:\n"
    message_bytes = message.encode()

    # Length-prefixed message
    prefixed = prefix + len(message_bytes).to_bytes(1, 'big') + message_bytes
    message_hash = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()

    # Sign with secp256k1
    private_key = coincurve.PrivateKey(private_key_bytes)
    signature = private_key.sign_recoverable(message_hash, hasher=None)

    return base64.b64encode(signature).decode()
```

### Transaction Message Format

The `!tx` message contains the unsigned transaction:

**Plaintext**: Base64-encoded raw transaction bytes
**Encrypted**: Using NaCl Box, then base64-encoded again

```python
# Taker sends tx
tx_bytes = bytes.fromhex(tx_hex)
tx_b64 = base64.b64encode(tx_bytes).decode()
encrypted = session.crypto.encrypt(tx_b64)  # Returns base64
```

### Signature Response Format

The `!sig` message contains maker signatures:

**Plaintext**: Base64-encoded signature (one per input)
**Multiple inputs**: Multiple `!sig` messages sent, one per input

```python
# Maker sends signatures
for sig_b64 in signatures:
    encrypted_sig = session.crypto.encrypt(sig_b64)
    await send_message(taker_nick, "sig", encrypted_sig)
```

### Input Index Mapping in CoinJoin

CoinJoin transactions have shuffled inputs. The maker must find their input indices:

```python
def find_input_indices(tx_inputs: list, our_utxos: list[tuple[str, int]]) -> dict:
    """Map our UTXOs to actual input indices in the transaction."""
    input_map = {}
    for idx, inp in enumerate(tx_inputs):
        # Transaction inputs store txid in little-endian
        txid_be = inp.txid[::-1].hex()
        key = (txid_be, inp.vout)
        if key in our_utxos:
            input_map[key] = idx
    return input_map
```

### Complete Protocol Sequence

```
Taker                           Maker
  |                               |
  |--- !fill (oid, amt, taker_pk, commit) -->|  PLAINTEXT
  |<-- !pubkey (maker_nacl_pk) ---|          PLAINTEXT + signature
  |                               |
  |--- !auth (encrypted reveal) ->|          ENCRYPTED
  |<-- !ioauth (encrypted) -------|          ENCRYPTED + signature
  |                               |
  |--- !tx (encrypted tx_b64) --->|          ENCRYPTED
  |<-- !sig (encrypted sig_b64) --|          ENCRYPTED (one per input)
  |                               |
  [Taker broadcasts final tx]
```

### Error Handling

Common failure modes and their causes:

| Error | Cause | Solution |
|-------|-------|----------|
| "Commitment does not match" | Wrong PoDLE formula | Use `s = k + e*x` convention |
| "btc_sig verification failed" | Signing wrong data | Sign OUR NaCl pubkey, not theirs |
| "Decryption failed" | Wrong key exchange | Ensure both sides use same NaCl keys |
| "Input not found in tx" | LE/BE txid confusion | Convert txid bytes to big-endian |

---

## References

- [Original JoinMarket Implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/)
- [JoinMarket Protocol Documentation](https://github.com/JoinMarket-Org/JoinMarket-Docs)
- [PoDLE Design](https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8)
- [Fidelity Bonds Design](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af)
- [BIP157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP158 - Compact Block Filters](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
