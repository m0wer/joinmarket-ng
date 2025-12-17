# Regtest CoinJoin Testing Guide

This document describes how to run a complete CoinJoin transaction on regtest with two makers and one taker.

## Prerequisites

- Docker and Docker Compose
- Python 3.14+ with the project dependencies installed
- Bitcoin Core regtest running via Docker

## Architecture Overview

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

The directory server routes messages between participants. Makers announce offers, and the taker initiates the CoinJoin by selecting makers and coordinating the transaction.

## Setup

### 1. Start Infrastructure

```bash
# Start Bitcoin Core regtest and directory server
docker compose up -d bitcoin directory-server

# Verify containers are running
docker ps
```

### 2. Fund Test Wallets

Generate blocks to fund the test wallets. The wallets use specific mnemonics for reproducibility:

```bash
# Mine some blocks to the test addresses
bitcoin-cli -regtest generatetoaddress 101 <address>
```

## Test Wallets

### Maker 1
- **Mnemonic**: `avoid whisper mesh corn already blur sudden fine planet chicken hover sniff`
- **Min size**: 100,000 sats
- **Fee contribution**: 1,000 sats
- **CJ fee**: 0.03%

### Maker 2
- **Mnemonic**: `minute faint grape plate stock mercy tent world space opera apple rocket`
- **Min size**: 100,000 sats
- **Fee contribution**: 1,500 sats
- **CJ fee**: 0.025%

### Taker
- **Mnemonic**: `burden notable love elephant orbit couch message galaxy elevator exile drop toilet`

## Running the Test

### 1. Start Makers

Start both makers in separate terminals (or background):

```bash
# Terminal 1 - Maker 1
cd /path/to/jm-refactor
PYTHONPATH="jmcore/src:jmwallet/src:maker/src" python3 -c "
from maker.cli import app
import sys
sys.argv = ['maker', 'start',
    '--mnemonic', 'avoid whisper mesh corn already blur sudden fine planet chicken hover sniff',
    '--network', 'regtest',
    '--rpc-url', 'http://127.0.0.1:18443',
    '--rpc-user', 'test',
    '--rpc-password', 'test',
    '--directory-servers', '127.0.0.1:5222',
    '--min-size', '100000',
    '--tx-fee-contribution', '1000',
    '--cj-fee-relative', '0.0003'
]
app()
" > /tmp/maker1.log 2>&1 &

# Terminal 2 - Maker 2
PYTHONPATH="jmcore/src:jmwallet/src:maker/src" python3 -c "
from maker.cli import app
import sys
sys.argv = ['maker', 'start',
    '--mnemonic', 'minute faint grape plate stock mercy tent world space opera apple rocket',
    '--network', 'regtest',
    '--rpc-url', 'http://127.0.0.1:18443',
    '--rpc-user', 'test',
    '--rpc-password', 'test',
    '--directory-servers', '127.0.0.1:5222',
    '--min-size', '100000',
    '--tx-fee-contribution', '1500',
    '--cj-fee-relative', '0.00025'
]
app()
" > /tmp/maker2.log 2>&1 &
```

### 2. Run Taker CoinJoin

Wait a few seconds for makers to connect to the directory server, then run the taker:

```bash
PYTHONPATH="jmcore/src:jmwallet/src:taker/src" python3 -m taker.cli coinjoin \
  --mnemonic "burden notable love elephant orbit couch message galaxy elevator exile drop toilet" \
  --network regtest \
  --rpc-url http://127.0.0.1:18443 \
  --rpc-user test \
  --rpc-password test \
  --directory 127.0.0.1:5222 \
  --amount 50000000 \
  --counterparties 2 \
  --log-level INFO
```

### 3. Expected Output

A successful CoinJoin will show:

```
14:00:19 | INFO     | Starting CoinJoin: 50000000 sats -> INTERNAL
14:00:29 | INFO     | Fetched 2 offers and 0 fidelity bonds
14:00:29 | INFO     | Selected 2 makers, total fee: 27,500 sats
14:00:29 | INFO     | Phase 1: Sending !fill to makers...
14:00:34 | INFO     | Phase 2: Sending !auth and receiving !ioauth...
14:00:39 | INFO     | Phase 3: Building transaction...
14:00:44 | INFO     | Phase 4: Collecting signatures...
14:00:44 | INFO     | Phase 5: Broadcasting transaction...
14:00:44 | INFO     | CoinJoin COMPLETE! txid: <txid>
```

### 4. Verify Transaction

```bash
# Check transaction in mempool or blockchain
bitcoin-cli -regtest getrawtransaction <txid> true
```

The transaction should have:
- **3 inputs**: 1 from taker + 2 from makers
- **6 outputs**: 3 equal-amount CoinJoin outputs + 3 change outputs

## Protocol Flow

The CoinJoin protocol follows these phases:

1. **Orderbook**: Taker fetches offers from makers via directory server
2. **Phase 1 (!fill)**: Taker selects makers and sends fill requests
3. **Phase 2 (!auth/!pubkey)**: Authentication and PoDLE commitment exchange
4. **Phase 3 (!ioauth)**: Makers provide their inputs and outputs
5. **Phase 4 (!tx/!sig)**: Transaction building and signature collection
6. **Phase 5 (broadcast)**: Taker broadcasts the signed transaction

## Troubleshooting

### Check Maker Logs

```bash
tail -f /tmp/maker1.log
tail -f /tmp/maker2.log
```

### Common Issues

1. **"Peerlist empty"**: Normal for NOT-SERVING-ONION mode. The taker listens for announcements instead.

2. **Signature verification failed**: Check that:
   - scriptCode is 25 bytes (no length prefix)
   - Signatures use low-S normalization (BIP 62/146)
   - `Prehashed(SHA256())` is used when signing pre-hashed sighash

3. **Input index mismatch**: CoinJoin inputs are shuffled. Makers must find their actual input indices in the final transaction.

## Key Implementation Details

### BIP 143 Sighash (P2WPKH)

The scriptCode for P2WPKH is 25 bytes:
```
OP_DUP OP_HASH160 <20-byte-pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
```

The sighash preimage adds `encode_varint(len(script_code))` before the scriptCode, so the scriptCode itself must NOT include a length prefix.

### Low-S Signature Normalization

Bitcoin requires signatures with S values in the lower half of the curve order (BIP 62/146):

```python
secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1_half_order = secp256k1_order // 2

if s > secp256k1_half_order:
    s = secp256k1_order - s
```

### Input Index Mapping

Since CoinJoin transactions shuffle inputs for privacy, makers must build an index map:

```python
input_index_map = {}
for idx, inp in enumerate(tx.inputs):
    txid = inp.txid_le[::-1].hex()  # Convert to big-endian hex
    input_index_map[(txid, inp.vout)] = idx
```

## Files Modified

Key files for the CoinJoin implementation:

- `maker/src/maker/bot.py` - Maker bot message handling
- `maker/src/maker/coinjoin.py` - Maker transaction signing
- `taker/src/taker/taker.py` - Taker CoinJoin orchestration
- `taker/src/taker/tx_builder.py` - Transaction construction
- `jmwallet/src/jmwallet/wallet/signing.py` - P2WPKH signing utilities
- `jmcore/src/jmcore/protocol.py` - Protocol message definitions
