# JoinMarket Protocol Documentation

This document consolidates the JoinMarket protocol specification, implementation details, and testing guide for the modern Python refactored implementation.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Wallet Design](#wallet-design)
4. [Messaging Protocol](#messaging-protocol)
5. [CoinJoin Protocol Flow](#coinjoin-protocol-flow)
6. [Encryption Protocol](#encryption-protocol)
7. [PoDLE (Proof of Discrete Log Equivalence)](#podle-proof-of-discrete-log-equivalence)
8. [Fidelity Bonds](#fidelity-bonds)
9. [Transaction Types](#transaction-types)
10. [Offer System](#offer-system)
11. [Testing Guide](#testing-guide)

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
                    │    Bitcoin Core      │
                    │     (via RPC)        │
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

```
Taker                                                          Maker
  |                                                               |
  |--- !fill <oid> <amount> <commitment> ------------------------>|
  |                                                               |
  |<-- !pubkey <maker_enc_pubkey> --------------------------------|
```

### Phase 3: Authentication (Encrypted)

```
Taker                                                          Maker
  |                                                               |
  |--- !auth <podle_revelation> --------------------------------->|
  |        (PoDLE proof + taker signature)                        |
  |                                                               |
  |<-- !ioauth <utxos> <cj_addr> <change_addr> <sig> -------------|
  |        (Maker's inputs and outputs)                           |
```

### Phase 4: Transaction (Encrypted)

```
Taker                                                          Maker
  |                                                               |
  |--- !tx <tx_hex> --------------------------------------------->|
  |        (Unsigned transaction)                                 |
  |                                                               |
  |<-- !sig <signatures> -----------------------------------------|
  |        (Maker's signatures for their inputs)                  |
```

### Phase 5: Broadcast

The taker:
1. Adds their own signatures
2. Assembles the final transaction
3. Broadcasts to the Bitcoin network

### Implementation Reference

The protocol flow is implemented in:
- `taker/src/taker/taker.py:292-449` - `do_coinjoin()` method
- `maker/src/maker/bot.py:265-377` - Message handlers

---

## Encryption Protocol

Private messages containing sensitive data are encrypted using NaCl (libsodium).

### Key Exchange

```
TAK: !fill <order_id> <amount> <taker_enc_pubkey>
MAK: !pubkey <maker_enc_pubkey>
```

Both parties derive a shared secret using Curve25519 ECDH and create a `Box` for authenticated encryption.

### Encrypted Messages

The following commands are always encrypted:
- `!auth` - PoDLE revelation and taker signature
- `!ioauth` - Maker's UTXOs and addresses
- `!tx` - Unsigned transaction
- `!sig` - Signatures

### Anti-MITM Protection

Each party signs their encryption pubkey with a Bitcoin key that corresponds to:
- **Taker**: One of their input UTXOs
- **Maker**: Their CoinJoin output address

This binds the encryption channel to the transaction participants.

---

## PoDLE (Proof of Discrete Log Equivalence)

PoDLE prevents Sybil attacks by requiring takers to commit to a UTXO ownership proof before makers reveal their UTXOs.

### Purpose

Without PoDLE, an attacker could:
1. Request CoinJoins from many makers
2. Collect their UTXO sets
3. Never complete the transaction
4. Link maker UTXOs across requests

### Protocol

1. **Taker generates commitment**: `C = H(P2)` where `P2 = k*J`
   - `k` = private key for a UTXO
   - `J` = NUMS (Nothing Up My Sleeve) point
   - `G` = Standard generator point

2. **Taker sends commitment** to maker in `!fill`

3. **Maker accepts** and sends their encryption pubkey

4. **Taker reveals** in `!auth`:
   - `P` = public key (k*G)
   - `P2` = commitment point (k*J)
   - `sig`, `e` = Schnorr proof that P and P2 have same discrete log

5. **Maker verifies**:
   - `H(P2) == C` (commitment matches)
   - Schnorr proof is valid
   - UTXO exists and is unspent

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

## Testing Guide

### Prerequisites

- Docker and Docker Compose
- Python 3.14+ with project dependencies
- Bitcoin Core regtest via Docker

### Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Maker 1    │────▶│ Directory Server │◀────│   Maker 2    │
└──────────────┘     └──────────────────┘     └──────────────┘
                              ▲
                              │
                     ┌──────────────┐
                     │    Taker     │
                     └──────────────┘
```

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
| `jmcore/src/jmcore/crypto.py` | Cryptographic primitives |
| `jmcore/src/jmcore/podle.py` | PoDLE generation and verification |
| `maker/src/maker/bot.py` | Maker message handling |
| `maker/src/maker/coinjoin.py` | Maker transaction signing |
| `taker/src/taker/taker.py` | Taker CoinJoin orchestration |
| `taker/src/taker/tx_builder.py` | Transaction construction |
| `jmwallet/src/jmwallet/wallet/signing.py` | P2WPKH signing utilities |

---

## References

- [Original JoinMarket Implementation](https://github.com/JoinMarket-Org/joinmarket-clientserver/)
- [JoinMarket Protocol Documentation](https://github.com/JoinMarket-Org/JoinMarket-Docs)
- [PoDLE Design](https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8)
- [Fidelity Bonds Design](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af)
