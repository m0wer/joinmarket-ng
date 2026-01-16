<p align="center">
  <img src="media/logo.svg" alt="JoinMarket NG Logo" width="200"/>
</p>

# JoinMarket NG

Modern, clean alternative implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/).

- Live orderbook: https://joinmarket-ng.sgn.space/
- Live docs: https://m0wer.github.io/joinmarket-ng/

## What is JoinMarket?

**Decentralized Bitcoin privacy tool that improves transaction privacy through CoinJoin.**

CoinJoin mixes multiple users' coins in a single transaction, making it difficult to trace who paid whom. Unlike centralized mixers, JoinMarket is peer-to-peer with no coordinator that could spy on you or censor your transactions.

### Two Ways to Use JoinMarket

**As a Taker (Privacy User)**
- Mix your coins to improve privacy
- You pay small fees to liquidity providers
- Quick: Single CoinJoin in minutes
- Or schedule multiple rounds for stronger privacy

**As a Maker (Liquidity Provider)**
- Earn fees by providing liquidity
- Run a bot that automatically participates in CoinJoins
- Passive income while improving your own privacy
- Fidelity bonds increase your earnings

### Why Use JoinMarket?

- **No central coordinator** - No one can spy on, censor, or steal your transactions
- **Real privacy** - You choose who to mix with, not a third party
- **Earn while you wait** - Run a maker bot and earn fees
- **Battle-tested protocol** - Compatible with the original JoinMarket implementation

## Quick Start

### Installation

**One-line install** (Linux/macOS):

```bash
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash
```

The installer will:
- Check and install system dependencies
- Install and configure Tor
- Set up JoinMarket-NG (both maker and taker by default)
- Create configuration files

### First Time Setup

After installation, configure your Bitcoin backend in `~/.joinmarket-ng/config.toml`:

```toml
[bitcoin]
# Option 1: Bitcoin Core (requires running full node)
backend_type = "descriptor_wallet"
rpc_url = "http://127.0.0.1:8332"
rpc_user = "your_user"
rpc_password = "your_password"

# Option 2: Neutrino (lightweight, no full node needed - BETA)
# backend_type = "neutrino"
# neutrino_url = "http://127.0.0.1:8334"
```

**Don't have Bitcoin Core?** Use Neutrino for a lightweight setup (requires ~500MB instead of ~900GB). See [INSTALL.md](./INSTALL.md) for Neutrino setup.

### Your First CoinJoin (as Taker)

1. **Create a wallet:**
   ```bash
   jm-wallet generate
   ```
   Save your recovery phrase in a safe place.

2. **Get a deposit address:**
   ```bash
   jm-wallet info
   ```
   Use the mixdepth 0 address shown.

3. **Fund your wallet** with the address from step 2. Wait for confirmations.

4. **Check your balance:**
   ```bash
   jm-wallet info
   ```

5. **Run your first CoinJoin:**
   ```bash
   jm-taker coinjoin \
     --amount 1000000 \
     --mixdepth 0 \
     --destination INTERNAL
   ```

   This will mix 1,000,000 sats (0.01 BTC) to an internal address for privacy.

**What happens during CoinJoin:**

- Taker finds makers offering liquidity
- Coordinates a collaborative transaction
- Your coins get mixed with others
- You pay a small fee (less than 1% with the default settings)
- Takes 2-10 minutes depending on confirmations

**For stronger privacy:** Run multiple CoinJoins across different mixdepths. See [Taker Guide](./taker/README.md) for schedules and tumbler mode.

### Earning Fees (as Maker)

Run a maker bot to earn fees by providing liquidity:

```bash
jm-maker start
```

The maker bot will:
- Announce your liquidity to the network
- Automatically participate in CoinJoins
- Earn fees from takers (you set the rates)
- Run 24/7 in the background

**Earnings:** Typical fees are 0.1-0.4% per CoinJoin. With fidelity bonds, you can get chosen more often by proving long-term commitment. See [Maker Guide](./maker/README.md) for configuration options.

## Next Steps

- **Taker:** [Complete taker guide](./taker/README.md) - Schedules, tumbler, advanced options
- **Maker:** [Complete maker guide](./maker/README.md) - Fee optimization, fidelity bonds
- **Installation:** [Detailed install guide](./INSTALL.md) - Docker, Neutrino, troubleshooting
- **Technical docs:** [DOCS.md](./DOCS.md) - Protocol details, architecture, security

## Why JoinMarket-NG?

This is a modern alternative implementation of JoinMarket, fully compatible with the original but with significant improvements:


**Key Improvements:**

- **No daemon, simpler setup** - Just run commands, no background services to manage
- **Run maker and taker simultaneously** - Huge privacy win, no suspicious gaps in offers
- **Light client support (Neutrino)** - No full node required (~500MB vs ~900GB)
- **Modern codebase** - Python 3.14+, full type hints, ~100% test coverage
- **Easier to audit** - Clean code, comprehensive tests, detailed documentation

**Full compatibility:** Works seamlessly with the original JoinMarket implementation. You can mix with users running either version.

See [DOCS.md](./DOCS.md) for detailed architectural differences and protocol documentation.

## Project Structure

```
joinmarket-ng/
├── jmcore/              # Shared library (crypto, protocol)
├── jmwallet/            # Wallet library (BIP32/39/84, backends)
├── directory_server/    # Directory/relay server
├── orderbook_watcher/   # Orderbook monitoring
├── maker/               # Maker bot (yield generator)
├── taker/               # Taker bot (CoinJoin orchestrator)
└── tests/               # End-to-end tests
```

## Security

### Reproducible Builds

All Docker images are built reproducibly using `SOURCE_DATE_EPOCH` timestamps. This allows anyone to verify that released images match the source code.

```bash
# Verify a release (checks GPG signatures and image digests)
./scripts/verify-release.sh 1.0.0

# Reproduce the build locally
./scripts/verify-release.sh 1.0.0 --reproduce
```

Releases are signed by trusted parties who have verified the build. See [DOCS.md](./DOCS.md#reproducible-builds) for details on verification and signing.

## Help & Community

- **Installation issues:** See [INSTALL.md](./INSTALL.md)
- **Usage questions:** Check component READMEs ([taker](./taker/README.md), [maker](./maker/README.md))
- **Technical details:** See [DOCS.md](./DOCS.md)
- **Community:**
  - Telegram: https://t.me/joinmarketorg
  - SimpleX: https://smp12.simplex.im/g#bx_0bFdk7OnttE0jlytSd73jGjCcHy2qCrhmEzgWXTk

## License

MIT License. See [LICENSE](./LICENSE) for details.
