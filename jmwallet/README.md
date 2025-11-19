# JoinMarket Wallet Library (jmwallet)

Modern Hierarchical Deterministic (HD) wallet implementation for JoinMarket refactor.

![Status](https://img.shields.io/badge/status-in_development-yellow.svg)

```
jmwallet/
├── src/jmwallet/
│   ├── backends/         # Blockchain backends (Bitcoin Core, Mempool)
│   ├── wallet/           # BIP32/39/84 implementation
│   └── __init__.py
├── tests/               # Unit tests
└── pyproject.toml       # Package metadata
```

## ✨ Features

- **Multi-backend architecture** (Bitcoin Core RPC, Mempool.space API)
- **No BerkeleyDB dependency** (works with Bitcoin Core v30+)
- **BIP32/BIP39/BIP84** HD wallet implementation
- **JoinMarket mixdepth support** (5 isolation levels)
- **P2WPKH address generation** (BIP173 bech32)
- **UTXO management + coin selection**
- **Transaction signing utilities** (P2WPKH inputs)

## ✅ Solving the BerkeleyDB Problem

Reference JoinMarket requires Bitcoin Core wallet (BerkeleyDB) for `importaddress`, which breaks on Bitcoin Core v30+.

**jmwallet solution:** Connect directly to Bitcoin Core's RPCs (`scantxoutset`, `getblockchaininfo`, etc.) — **no wallet.dat needed!** This makes it compatible with modern Bitcoin Core without deprecated settings.

## 📦 Installation

```bash
cd jmwallet
pip install -e .[dev]
```

## 🚀 Quick Start

```python
import asyncio
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService

async def main():
    backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test",
    )

    wallet = WalletService(
        mnemonic="abandon abandon ... about",
        backend=backend,
        network="regtest",
    )

    await wallet.sync_all()
    balance = await wallet.get_total_balance()
    print(f"Balance: {balance:,} sats")

    utxos = wallet.select_utxos(mixdepth=0, target_amount=50_000)
    print(f"Selected {len(utxos)} UTXOs")

asyncio.run(main())
```

## 🔌 Backends

### Bitcoin Core Backend
- Uses `scantxoutset` RPC to find UTXOs
- No need to import addresses into wallet
- Works with v30+ (descriptor wallets)

### Mempool Backend
- Uses Mempool.space API
- No local node required
- Great for beginners (tradeoff: privacy)

(Upcoming: Electrum backend)

## 🧪 Testing

```bash
# Unit tests
pytest tests/ -v

# Type checking
mypy src/

# Linting
ruff check src/ tests/
```

## 📚 Components

| Module | Description |
|--------|-------------|
| `wallet/bip32.py` | HD key derivation (BIP32) |
| `wallet/address.py` | Bech32 address generation (BIP173) |
| `wallet/service.py` | Wallet operations (balance, UTXOs, mixdepths) |
| `wallet/signing.py` | P2WPKH transaction signing |
| `backends/bitcoin_core.py` | Bitcoin Core RPC backend |
| `backends/mempool.py` | Mempool.space API backend |

## 🛡️ Security Notes

- All derivations and signing use `cryptography` (secp256k1)
- PoDLE verification and transaction verification handled in `maker` module
- Do not use real mainnet mnemonics for testing
- Transaction signing currently supports P2WPKH inputs

## 🤝 Contributing

1. Fork and clone the repo
2. Create a feature branch
3. Run tests (`pytest`, `mypy`, `ruff`)
4. Submit a PR with description and tests

## 📄 License

MIT License (see root LICENSE)
