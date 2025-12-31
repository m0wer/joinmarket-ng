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
mkdir -p ~/.joinmarket-ng/wallets
jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/maker.mnemonic
```

**IMPORTANT**: Write down the displayed mnemonic - it's your only backup!

See [jmwallet README](../jmwallet/README.md) for wallet management details.

### 2. Check Balance & Get Deposit Address

```bash
# View balance and addresses
jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic --backend neutrino

# Or use jm-maker to get a specific address
jm-maker generate-address --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic
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
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
  --backend-type neutrino
```

#### Option B: Bitcoin Core Full Node

For maximum security. Create an environment file to avoid credentials in shell history:

```bash
cat > ~/.joinmarket-ng/bitcoin.env << EOF
export BITCOIN_RPC_URL=http://127.0.0.1:8332
export BITCOIN_RPC_USER=your_rpc_user
export BITCOIN_RPC_PASSWORD=your_rpc_password
EOF
chmod 600 ~/.joinmarket-ng/bitcoin.env
```

Start maker bot:

```bash
source ~/.joinmarket-ng/bitcoin.env
jm-maker start \
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
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

- **Fee model**: Relative fees (0.1%)
- **Minimum size**: 100,000 sats

### Offer Types and Fees

JoinMarket supports two fee models. The maker bot **automatically detects** which model to use based on which fee parameter you provide:

#### Relative Fees (Default)
Charge a percentage of the CoinJoin amount:
- **Auto-selected when**: You provide `--cj-fee-relative` (or neither fee parameter)
- **Offer type**: `sw0reloffer`
- **Default**: 0.1% (0.001)
- **Example**: 0.2% of 1 BTC = 200,000 sats
- **Pros**: Scales with transaction size, competitive for large amounts
- **Cons**: May earn less on small transactions

#### Absolute Fees
Charge a fixed satoshi amount regardless of CoinJoin size:
- **Auto-selected when**: You provide `--cj-fee-absolute`
- **Offer type**: `sw0absoffer`
- **Default**: Not used (relative is default)
- **Example**: Fixed 1000 sats per CoinJoin
- **Pros**: Predictable earnings, better for small transactions
- **Cons**: May be uncompetitive for large amounts

**Important**: Only provide ONE fee parameter. If you provide both, the maker will exit with an error.

### Custom Fee Settings

```bash
# Relative fee (0.2%) - auto-selects sw0reloffer
jm-maker start \
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
  --backend-type neutrino \
  --cj-fee-relative 0.002 \
  --min-size 200000

# Absolute fee (1000 sats) - auto-selects sw0absoffer
jm-maker start \
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
  --backend-type neutrino \
  --cj-fee-absolute 1000 \
  --min-size 200000
```

### Fidelity Bonds (Advanced)

Increase offer visibility by locking bitcoin for a period. See wallet CLI:

```bash
# Generate bond address (saves to registry for auto-discovery)
jm-wallet generate-bond-address \
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
  --locktime 1735689600

# List existing bonds
jm-wallet list-bonds --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic

# View registry entries
jm-wallet registry-list
```

**Auto-discovery**: Bonds created with `generate-bond-address` are saved to the bond registry (`~/.joinmarket-ng/fidelity_bonds.json`). The maker bot **automatically discovers** these bonds at startup - no need to specify locktimes manually.

If you need to manually specify locktimes (e.g., for bonds created outside this tool):

```bash
jm-maker start \
  --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic \
  --fidelity-bond-locktimes 1735689600
```

## Docker Deployment

### With Neutrino and Tor (Ephemeral Hidden Service)

Recommended setup with ephemeral hidden service for privacy.

**1. Create torrc configuration:**

```bash
mkdir -p tor/conf
cat > tor/conf/torrc << 'EOF'
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
DataDirectory /var/lib/tor
Log notice stdout
EOF
```

**2. Create docker-compose.yml:**

```yaml
services:
  tor:
    image: ghcr.io/m0wer/docker-tor:latest
    volumes:
      - ./tor/conf/torrc:/etc/tor/torrc:ro
      - tor-data:/var/lib/tor

  neutrino:
    image: ghcr.io/m0wer/neutrino-api
    environment:
      NETWORK: mainnet
    volumes:
      - neutrino-data:/data/neutrino

  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC_FILE: /home/jm/.joinmarket-ng/wallets/maker.mnemonic
      BACKEND_TYPE: neutrino
      NEUTRINO_URL: http://neutrino:8334
      TOR_SOCKS_HOST: tor
      TOR_SOCKS_PORT: 9050
      TOR_CONTROL_ENABLED: "true"
      TOR_CONTROL_HOST: tor
      TOR_CONTROL_PORT: 9051
      TOR_COOKIE_PATH: /var/lib/tor/control_auth_cookie
      ONION_SERVING_HOST: 0.0.0.0
      ONION_SERVING_PORT: 27183
    volumes:
      - ~/.joinmarket-ng:/home/jm/.joinmarket-ng
      - tor-data:/var/lib/tor:ro  # Read-only access to cookie
    depends_on:
      - neutrino
      - tor

volumes:
  neutrino-data:
  tor-data:
```

**3. Start services:**

```bash
docker-compose up -d
```

The maker will:
- Connect to directory servers through Tor SOCKS proxy (port 9050)
- Generate a fresh `.onion` address via Tor control port (port 9051)
- Advertise this ephemeral address to takers
- Clean up the hidden service when stopped

### With Neutrino (Simple)

If you already have Tor running elsewhere:

```yaml
services:
  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC_FILE: /home/jm/.joinmarket-ng/wallets/maker.mnemonic
      BACKEND_TYPE: neutrino
      NEUTRINO_URL: http://neutrino:8334
    volumes:
      - ~/.joinmarket-ng:/home/jm/.joinmarket-ng
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

### With Bitcoin Core and Tor

**1. Create torrc configuration (if not already created):**

```bash
mkdir -p tor/conf
cat > tor/conf/torrc << 'EOF'
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
DataDirectory /var/lib/tor
Log notice stdout
EOF
```

**2. Create docker-compose.yml:**

```yaml
services:
  tor:
    image: ghcr.io/m0wer/docker-tor:latest
    volumes:
      - ./tor/conf/torrc:/etc/tor/torrc:ro
      - tor-data:/var/lib/tor

  bitcoind:
    image: kylemanna/bitcoind
    volumes:
      - bitcoin-data:/bitcoin/.bitcoin

  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC_FILE: /home/jm/.joinmarket-ng/wallets/maker.mnemonic
      BACKEND_TYPE: full_node
      BITCOIN_RPC_URL: http://bitcoind:8332
      BITCOIN_RPC_USER: rpcuser
      BITCOIN_RPC_PASSWORD: rpcpassword
      TOR_SOCKS_HOST: tor
      TOR_SOCKS_PORT: 9050
      TOR_CONTROL_ENABLED: "true"
      TOR_CONTROL_HOST: tor
      TOR_CONTROL_PORT: 9051
      TOR_COOKIE_PATH: /var/lib/tor/control_auth_cookie
      ONION_SERVING_HOST: 0.0.0.0
      ONION_SERVING_PORT: 27183
    volumes:
      - ~/.joinmarket-ng:/home/jm/.joinmarket-ng
      - tor-data:/var/lib/tor:ro
    depends_on:
      - bitcoind
      - tor

volumes:
  bitcoin-data:
  tor-data:
```

**3. Start services:**

```bash
docker-compose up -d
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MNEMONIC_FILE` | - | Path to mnemonic file (recommended) |
| `MNEMONIC` | - | Direct mnemonic phrase (not recommended for production) |
| `BACKEND_TYPE` | `full_node` | Backend: `full_node` or `neutrino` |
| `NETWORK` | `mainnet` | Protocol network for handshakes |
| `BITCOIN_NETWORK` | `$NETWORK` | Bitcoin network for address generation |
| `BITCOIN_RPC_URL` | `http://localhost:8332` | Bitcoin Core RPC URL |
| `BITCOIN_RPC_USER` | - | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASSWORD` | - | Bitcoin Core RPC password |
| `NEUTRINO_URL` | `http://localhost:8334` | Neutrino REST API URL |
| `DIRECTORY_SERVERS` | (mainnet defaults) | Comma-separated list of directory servers |
| `MIN_SIZE` | `100000` | Minimum CoinJoin size in sats |
| `CJ_FEE_RELATIVE` | `0.001` | Relative fee (0.001 = 0.1%) - auto-selects relative offer type |
| `CJ_FEE_ABSOLUTE` | - | Absolute fee in sats - auto-selects absolute offer type if set |
| `TX_FEE_CONTRIBUTION` | `1000` | Transaction fee contribution in sats |
| `TOR_SOCKS_HOST` | `127.0.0.1` | Tor SOCKS proxy host |
| `TOR_SOCKS_PORT` | `9050` | Tor SOCKS proxy port |
| `TOR_CONTROL_ENABLED` | `false` | Enable ephemeral hidden service via Tor control port |
| `TOR_CONTROL_HOST` | `127.0.0.1` | Tor control port host |
| `TOR_CONTROL_PORT` | `9051` | Tor control port |
| `TOR_COOKIE_PATH` | `/var/lib/tor/control_auth_cookie` | Path to Tor control cookie |
| `ONION_SERVING_HOST` | `127.0.0.1` | Host to bind for incoming onion connections |
| `ONION_SERVING_PORT` | `27183` | Port for incoming onion connections |
| `FIDELITY_BOND_LOCKTIMES` | - | Comma-separated Unix timestamps for bond locktimes |
| `SENSITIVE_LOGGING` | - | Enable sensitive logging (set to `1` or `true`) |

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
| `--cj-fee-relative` | 0.001 | Relative fee (0.001 = 0.1%) - auto-selects relative offers |
| `--cj-fee-absolute` | - | Absolute fee in sats - auto-selects absolute offers |
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
- Check balance: `jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/maker.mnemonic`
- Need at least 100,000 sats per mixdepth by default

**"Failed to connect to directory server"**
- Ensure Tor is running
- Check network connectivity

**"Transaction verification failed"**
- Safety feature - invalid transaction from taker
- Your funds are safe, no action needed
