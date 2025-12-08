# JoinMarket Maker Bot (maker)

Modern maker (yield generator) implementation for JoinMarket refactor.

![Status](https://img.shields.io/badge/status-in_progress-yellow.svg)

```
maker/
├── src/maker/
│   ├── bot.py              # Main maker bot
│   ├── coinjoin.py         # CoinJoin session handler
│   ├── offers.py           # Offer management
│   ├── podle.py            # PoDLE verification
│   ├── tx_verification.py  # Critical transaction checks
│   └── config.py           # Maker configuration
├── tests/
│   ├── test_tx_verification.py
│   └── integration/
└── pyproject.toml
```

## 🔑 Key Features

- **Protocol-compatible maker bot** for JoinMarket
- **PoDLE verification** (anti-sybil)
- **Transaction verification** (prevents loss of funds)
- **Wallet integration** with jmwallet (no Bitcoin Core wallet)
- **Offer management** based on mixdepth balances
- **Docker + E2E tests** with Bitcoin regtest

## ⚠️ Status

- Transaction signing implementation **in progress**
- End-to-end tests **on regtest** required before use
- Not ready for mainnet without completion + audit

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -e ../jmwallet
pip install -e .[dev]
```

### 2. Start test environment

```bash
cd ../
docker-compose up -d bitcoin directory orderbook-watcher
# Wait for Bitcoin to mine 101 blocks (~30s)
```

### 3. Run maker tests

```bash
pytest tests/test_tx_verification.py -v
pytest tests/integration/test_wallet_bitcoin_core.py -v
```

## 🔐 Security Components

| Module | Purpose |
|--------|---------|
| `podle.py` | Verifies PoDLE proofs from takers (anti-sybil) |
| `tx_verification.py` | **Critical**: ensures no loss of funds before signing |
| `coinjoin.py` | Handles !fill / !auth / !tx / !sig protocol flow |
| `offers.py` | Creates/manages liquidity offers |
| `bot.py` | Connects to directory servers, manages sessions |

## ✔️ Transaction Verification Highlights

- Ensures all maker inputs included
- Validates CJ + change outputs and amounts
- Rejects negative profit scenarios
- All logic backed by unit tests

## 🧪 Testing

```bash
# Unit tests
pytest tests/test_tx_verification.py -v

# Integration tests (requires Bitcoin Core)
pytest tests/integration/test_wallet_bitcoin_core.py -v
```

## 🧱 Docker Compose

Root-level `docker-compose.yml` spins up:
- `bitcoin` (regtest node)
- `directory` server
- `orderbook-watcher`

Maker bot can be run alongside via future container or direct CLI.
