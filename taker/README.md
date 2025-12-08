# JoinMarket Taker Client (taker)

Modern taker (CoinJoin initiator) implementation for JoinMarket refactor.

![Status](https://img.shields.io/badge/status-in_progress-yellow.svg)

```
taker/
├── src/taker/
│   ├── taker.py        # Main taker client
│   ├── orderbook.py    # Orderbook management & maker selection
│   ├── tx_builder.py   # CoinJoin transaction construction
│   ├── podle.py        # PoDLE commitment generation
│   ├── config.py       # Taker configuration
│   └── cli.py          # Command-line interface
├── tests/
│   ├── test_config.py
│   ├── test_orderbook.py
│   └── test_tx_builder.py
└── pyproject.toml
```

## Key Features

- **Protocol-compatible taker client** for JoinMarket
- **PoDLE commitment generation** (anti-sybil via jmcore)
- **Smart maker selection** with fee limits and fidelity bond weighting
- **Transaction building** with input/output shuffling for privacy
- **Tumbler support** with schedule-based multi-CoinJoin execution
- **Wallet integration** with jmwallet (no Bitcoin Core wallet)

## Status

- Transaction signing implementation **in progress**
- End-to-end tests **on regtest** required before use
- Not ready for mainnet without completion + audit

## Quick Start

### 1. Install dependencies

```bash
pip install -e ../jmcore
pip install -e ../jmwallet
pip install -e .[dev]
```

### 2. Start test environment

```bash
cd ../
docker-compose up -d bitcoin directory orderbook-watcher
# Wait for Bitcoin to mine 101 blocks (~30s)
```

### 3. Run taker tests

```bash
pytest tests/test_config.py -v
pytest tests/test_orderbook.py -v
pytest tests/test_tx_builder.py -v
```

## CLI Usage

### Single CoinJoin

```bash
jm-taker coinjoin \
    --amount 1000000 \
    --destination bcrt1q... \
    --mixdepth 0 \
    --counterparties 3 \
    --rpc-url http://localhost:18443 \
    --rpc-user test \
    --rpc-password test
```

Environment variables:
- `MNEMONIC` - BIP39 mnemonic phrase (required)
- `BITCOIN_RPC_URL`, `BITCOIN_RPC_USER`, `BITCOIN_RPC_PASSWORD`

### Tumbler (Schedule-based)

```bash
jm-taker tumble schedule.json \
    --rpc-url http://localhost:18443 \
    --rpc-user test \
    --rpc-password test
```

Schedule format (`schedule.json`):
```json
{
    "entries": [
        {
            "mixdepth": 0,
            "amount": 0.5,
            "counterparty_count": 3,
            "destination": "INTERNAL",
            "wait_time": 60
        },
        {
            "mixdepth": 1,
            "amount": 1000000,
            "counterparty_count": 4,
            "destination": "bcrt1q...",
            "wait_time": 0
        }
    ]
}
```

### Wallet Info

```bash
jm-taker wallet-info \
    --rpc-url http://localhost:18443 \
    --rpc-user test \
    --rpc-password test
```

## Components

| Module | Purpose |
|--------|---------|
| `taker.py` | Main CoinJoin protocol orchestration |
| `orderbook.py` | Orderbook management and maker selection |
| `tx_builder.py` | CoinJoin transaction construction |
| `podle.py` | PoDLE commitment generation (via jmcore) |
| `config.py` | Configuration models |
| `cli.py` | Command-line interface |

## CoinJoin Protocol Flow

```
Taker                           Maker
  │                               │
  │───── !fill (amount, C) ──────►│
  │                               │
  │◄──── !pubkey (encryption) ────│
  │                               │
  │── !auth (C, revelation, P) ──►│
  │                               │
  │◄─── !ioauth (UTXOs, addrs) ───│
  │                               │
  │──────── !tx (unsigned) ──────►│
  │                               │
  │◄───── !sig (signatures) ──────│
  │                               │
  │       [broadcast tx]          │
  └───────────────────────────────┘
```

Where:
- `C` = PoDLE commitment (H(P2))
- `revelation` = PoDLE proof (P, P2, sig, e, utxo)
- `P` = taker's encryption pubkey

## Maker Selection Algorithms

The orderbook manager supports multiple selection strategies:

1. **Random** - Uniform random selection
2. **Cheapest** - Select by lowest fee
3. **Weighted** - Exponential weighting by inverse fee
4. **Fidelity Bond Weighted** - Weight by bond value (default)

```python
from taker.orderbook import OrderbookManager

manager = OrderbookManager(max_cj_fee)
selected, total_fee = manager.select_makers(cj_amount=1_000_000, n=3)
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `counterparty_count` | 3 | Number of makers to use |
| `minimum_makers` | 2 | Minimum makers required |
| `max_cj_fee.abs_fee` | 50,000 | Max absolute fee (sats) |
| `max_cj_fee.rel_fee` | 0.001 | Max relative fee (0.1%) |
| `tx_fee_factor` | 3.0 | Multiplier for tx fee estimate |
| `taker_utxo_age` | 5 | Min confirmations for PoDLE UTXO |
| `taker_utxo_amtpercent` | 20 | Min UTXO value as % of CJ amount |
| `maker_timeout_sec` | 60 | Timeout waiting for maker response |
| `order_wait_time` | 10.0 | Seconds to wait for orderbook |

## Testing

```bash
# Unit tests
pytest tests/test_config.py -v
pytest tests/test_orderbook.py -v
pytest tests/test_tx_builder.py -v

# All tests with coverage
pytest --cov=taker --cov-report=html
```

## Docker

### Build

```bash
docker build -t jm-taker -f Dockerfile ..
```

### Run

```bash
docker run --rm \
    -e MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
    -e NETWORK=regtest \
    -e BITCOIN_RPC_URL=http://host.docker.internal:18443 \
    -e BITCOIN_RPC_USER=test \
    -e BITCOIN_RPC_PASSWORD=test \
    -e DIRECTORY_SERVERS=host.docker.internal:5222 \
    jm-taker coinjoin --amount 1000000 --destination bcrt1q...
```

### Docker Compose

From root directory:

```bash
# Start with taker profile
docker-compose --profile taker up taker

# Or run a single CoinJoin
docker-compose --profile taker run taker \
    jm-taker coinjoin --amount 1000000 --destination bcrt1q...
```
