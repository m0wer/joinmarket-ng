<p align="center">
  <img src="media/logo.svg" alt="JoinMarket NG Logo" width="200"/>
</p>

# JoinMarket NG

Modern implementation of [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver/) - decentralized Bitcoin privacy through CoinJoin.

- Live orderbook: https://joinmarket-ng.sgn.space/
- Live docs: https://m0wer.github.io/joinmarket-ng/

## What It Is

- **CoinJoin**: Mix your coins with others to break transaction history
- **Decentralized**: No central coordinator - taker coordinates peer-to-peer
- **Earn or spend**: Makers earn fees providing liquidity, takers pay fees for privacy

## What It Isn't

- Not a custodial mixer (you control your keys)
- Not a centralized tumbler service
- Not bulletproof - multiple rounds recommended for stronger privacy

## Quick Start

**Install** (Linux/macOS):

```bash
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash
```

**Configure** (`~/.joinmarket-ng/config.toml`):

```toml
[bitcoin]
backend_type = "descriptor_wallet"  # or "neutrino" for light client
rpc_url = "http://127.0.0.1:8332"
rpc_user = "your_user"
rpc_password = "your_password"
```

**Create wallet**:

```bash
jm-wallet generate
```

**Run your first CoinJoin** (as taker):

```bash
jm-wallet info                    # Get deposit address, fund it
jm-taker coinjoin --amount 1000000 --mixdepth 0 --destination INTERNAL
```

**Or earn fees** (as maker):

```bash
jm-maker start
```

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](./INSTALL.md) | Full installation guide, backends, Tor setup |
| [DOCS.md](./DOCS.md) | Protocol, architecture, security, development |
| [maker/README.md](./maker/README.md) | Maker bot configuration and operation |
| [taker/README.md](./taker/README.md) | Taker options, schedules, tumbler mode |
| [directory_server/README.md](./directory_server/README.md) | Directory server setup |
| [orderbook_watcher/README.md](./orderbook_watcher/README.md) | Orderbook monitoring |

## Why JoinMarket-NG?

This is a modern alternative to the reference implementation, fully compatible but with key improvements:

**Cross-compatible**: Makers running JoinMarket-NG are automatically discovered by takers using the legacy implementation, and vice versa. The wire protocol is 100% compatible, so you can seamlessly join the existing JoinMarket network.

- **No daemon** - just run commands, no background services
- **Run maker + taker simultaneously** - no suspicious gaps in offers
- **Light client support** - Neutrino backend, no full node required
- **Modern codebase** - Python 3.14+, full type hints, ~100% test coverage

See [DOCS.md](./DOCS.md#joinmarket-ng) for detailed comparison.

## Community

- Telegram: https://t.me/joinmarketorg
- SimpleX: https://smp12.simplex.im/g#bx_0bFdk7OnttE0jlytSd73jGjCcHy2qCrhmEzgWXTk

## License

MIT License. See [LICENSE](./LICENSE).
