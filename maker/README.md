# JoinMarket Maker Bot

Earn fees by providing liquidity for CoinJoin transactions. Makers passively earn bitcoin while enhancing network privacy.

## Installation

```bash
pip install -e ../jmcore ../jmwallet .
```

## Quick Start

### 1. Create a Wallet

Generate an encrypted wallet file:

```bash
mkdir -p ~/.jm/wallets
jm-wallet generate --save --prompt-password --output ~/.jm/wallets/maker.mnemonic
```

**IMPORTANT**: Write down the displayed mnemonic - it's your only backup!

See [jmwallet README](../jmwallet/README.md) for wallet management details.

### 2. Check Balance & Get Deposit Address

```bash
# View balance and addresses
jm-wallet info --mnemonic-file ~/.jm/wallets/maker.mnemonic --backend neutrino

# Or use jm-maker to get a specific address
jm-maker generate-address --mnemonic-file ~/.jm/wallets/maker.mnemonic
```

### 3. Fund Your Wallet

Send bitcoin to displayed addresses. For best results, spread funds across multiple mixdepths (0-4).

**Minimum**: ~100,000 sats per mixdepth to create offers.

### 4. Start Earning Fees

#### Option A: Neutrino Backend (Recommended for Beginners)

Start Neutrino server:

```bash
docker run -d \
  --name neutrino \
  -p 8334:8334 \
  -v neutrino-data:/data/neutrino \
  -e NETWORK=mainnet \
  -e LOG_LEVEL=info \
  ghcr.io/m0wer/neutrino-api
```

**Note**: Pre-built binaries available at [m0wer/neutrino-api releases](https://github.com/m0wer/neutrino-api/releases).

Start maker bot:

```bash
jm-maker start \
  --mnemonic-file ~/.jm/wallets/maker.mnemonic \
  --backend-type neutrino
```

#### Option B: Bitcoin Core Full Node

For maximum security. Create an environment file to avoid credentials in shell history:

```bash
cat > ~/.jm/bitcoin.env << EOF
export BITCOIN_RPC_URL=http://127.0.0.1:8332
export BITCOIN_RPC_USER=your_rpc_user
export BITCOIN_RPC_PASSWORD=your_rpc_password
EOF
chmod 600 ~/.jm/bitcoin.env
```

Start maker bot:

```bash
source ~/.jm/bitcoin.env
jm-maker start \
  --mnemonic-file ~/.jm/wallets/maker.mnemonic \
  --backend-type full_node
```

The bot will:
- Sync your wallet
- Create offers based on available balance
- Connect to directory servers via Tor
- Wait for takers and earn fees automatically

## Configuration

### Default Fee Settings

The defaults are sensible for most users:

- **Relative fee**: 0.1% (0.001)
- **Absolute fee**: 500 sats
- **Minimum size**: 100,000 sats

### Custom Fee Settings

```bash
jm-maker start \
  --mnemonic-file ~/.jm/wallets/maker.mnemonic \
  --backend-type neutrino \
  --cj-fee-relative 0.002 \
  --cj-fee-absolute 1000 \
  --min-size 200000
```

### Fidelity Bonds (Advanced)

Increase offer visibility by locking bitcoin for a period. See wallet CLI:

```bash
# Generate bond address
jm-wallet generate-bond-address \
  --mnemonic-file ~/.jm/wallets/maker.mnemonic \
  --locktime 1735689600

# List existing bonds
jm-wallet list-bonds --mnemonic-file ~/.jm/wallets/maker.mnemonic
```

Specify bond locktimes when starting:

```bash
jm-maker start \
  --mnemonic-file ~/.jm/wallets/maker.mnemonic \
  --fidelity-bond-locktimes 1735689600
```

## Docker Deployment

### With Neutrino

```yaml
services:
  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC_FILE: /wallets/maker.mnemonic
      BACKEND_TYPE: neutrino
      NEUTRINO_URL: http://neutrino:8334
    volumes:
      - ~/.jm/wallets:/wallets:ro
    depends_on:
      - neutrino
      - tor

  neutrino:
    image: ghcr.io/m0wer/neutrino-api
    environment:
      NETWORK: mainnet
    volumes:
      - neutrino-data:/data/neutrino

  tor:
    image: dperson/torproxy

volumes:
  neutrino-data:
```

### With Bitcoin Core

```yaml
services:
  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC_FILE: /wallets/maker.mnemonic
      BACKEND_TYPE: full_node
      BITCOIN_RPC_URL: http://bitcoind:8332
      BITCOIN_RPC_USER: rpcuser
      BITCOIN_RPC_PASSWORD: rpcpassword
    volumes:
      - ~/.jm/wallets:/wallets:ro
    depends_on:
      - bitcoind
      - tor

  bitcoind:
    image: kylemanna/bitcoind
    volumes:
      - bitcoin-data:/bitcoin/.bitcoin

  tor:
    image: dperson/torproxy

volumes:
  bitcoin-data:
```

Run with:

```bash
docker-compose up -d
```

## CLI Reference

```bash
# Start maker bot
jm-maker start [OPTIONS]

# Generate receive address
jm-maker generate-address [OPTIONS]

# See all options
jm-maker start --help
```

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `--mnemonic-file` | - | Path to encrypted wallet file |
| `--backend-type` | full_node | Backend: full_node or neutrino |
| `--cj-fee-relative` | 0.001 | Relative fee (0.001 = 0.1%) |
| `--cj-fee-absolute` | 500 | Absolute fee in sats |
| `--min-size` | 100000 | Minimum CoinJoin size in sats |

Use env vars for RPC credentials (see jmwallet README).

## Security

- Wallet files are encrypted - keep your password safe
- Bot verifies all transactions before signing
- All directory connections go through Tor
- Never expose your mnemonic or share wallet files
- File permissions automatically set to 600

## Troubleshooting

**"No offers created"**
- Check balance: `jm-wallet info --mnemonic-file ~/.jm/wallets/maker.mnemonic`
- Need at least 100,000 sats per mixdepth by default

**"Failed to connect to directory server"**
- Ensure Tor is running
- Check network connectivity

**"Transaction verification failed"**
- Safety feature - invalid transaction from taker
- Your funds are safe, no action needed
