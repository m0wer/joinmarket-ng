# JoinMarket Maker Bot

Earn fees by providing liquidity for CoinJoin transactions. Makers passively earn bitcoin while enhancing network privacy.

## Installation

See [INSTALL.md](../INSTALL.md) for complete installation instructions including:
- Automated installation with `install.sh`
- Virtual environment setup
- Backend setup (Bitcoin Core or Neutrino)
- Tor configuration

**Quick install** (if you already have the repo):

```bash
cd joinmarket-ng
source jmvenv/bin/activate  # If you used install.sh
# OR create venv: python3 -m venv jmvenv && source jmvenv/bin/activate
cd maker
pip install -e ../jmcore ../jmwallet .
```

## Prerequisites

**Tor is REQUIRED for production use.** Makers need Tor for privacy and to advertise .onion addresses for direct peer connections.

See [INSTALL.md - Tor Setup](../INSTALL.md#tor-setup) for installation and configuration instructions.

The maker bot tries to auto-detect Tor configuration. For manual setup, see [Environment Variables](#environment-variables).

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

#### Option A: Bitcoin Core Full Node (Recommended)

For maximum trustlessness, privacy, and compatibility with all takers. Create an environment file to avoid credentials in shell history:

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

#### Option B: Neutrino Backend

Lightweight alternative if you cannot run a full node. Note that Neutrino makers can only participate in CoinJoins with takers that support `neutrino_compat` mode.

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

The bot will:
- Sync your wallet
- Create offers based on available balance
- Create an ephemeral Tor .onion address (if Tor control available)
- Connect to directory servers and wait for takers

> **⚠️ Production Warning:** Without Tor control access, maker falls back to `NOT-SERVING-ONION` mode (all traffic via directory). Check logs for Tor warnings.

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

## Migrating from JoinMarket Reference Implementation

If you have an existing maker on the reference implementation (JoinMarket-Org/joinmarket-clientserver), you can migrate using your 12-word mnemonic.

### Quick Migration Steps

1. **Save your mnemonic** to a file on the host:

```bash
mkdir -p ~/.joinmarket-ng/wallets
# Edit and paste your 12-word mnemonic (plaintext, see below for encryption)
vim ~/.joinmarket-ng/wallets/maker.mnemonic
```

2. **Register your existing fidelity bond** (if you have one):

Find your bond info from the old maker (path like `m/84'/0'/0'/2/123:1767225600`).
You can use `wallet-tool.py`. Then:

```bash
docker exec -it <maker-container> jm-wallet generate-bond-address \
  --mnemonic-file /home/jm/.joinmarket-ng/wallets/maker.mnemonic \
  --locktime 1767225600 \
  --index 123
```

This verifies the address and adds it to the bond registry for auto-discovery.

3. **Sync bond status** from the blockchain:

```bash
docker exec -it <maker-container> jm-wallet registry-sync \
  --mnemonic-file /home/jm/.joinmarket-ng/wallets/maker.mnemonic
```

4. **Restart the maker** - it will automatically discover and use your bond.

### Key Differences

- **No wallet.jmdat file**: JoinMarket-NG uses only the mnemonic + blockchain state
- **Bond registry**: Fidelity bonds tracked in `~/.joinmarket-ng/fidelity_bonds.json`
- **Stateless design**: Everything derived from mnemonic on each startup
- **Same derivation paths**: Compatible with reference implementation (BIP84)

### Encrypting Your Mnemonic (Optional)

For better security, encrypt your mnemonic file:

```bash
jm-wallet generate \
  --mnemonic "your 12 word phrase here" \
  --save \
  --prompt-password \
  --output ~/.joinmarket-ng/wallets/maker.mnemonic
```

Then use `--password` or `MNEMONIC_PASSWORD` env var when running commands.

## Docker Deployment

A production-ready `docker-compose.yml` is provided in this directory with:

- **Bitcoin Core backend** for maximum trustlessness and compatibility
- **Tor** with control port for ephemeral .onion address creation
- **Logging limits** to prevent disk exhaustion from log flooding
- **Resource limits** for CPU and memory
- **Health checks** for service dependencies

> **Note**: Bitcoin Core is strongly recommended for makers. Neutrino-based makers can only
> participate in CoinJoins with takers that support `neutrino_compat` mode, limiting your
> potential earnings and network compatibility.

### Quick Start

1. **Create Tor configuration directory:**

```bash
mkdir -p tor/conf tor/run
```

2. **Create `tor/conf/torrc`:**

```torc
# Minimal Tor configuration for JoinMarket maker
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
DataDirectory /var/lib/tor
Log notice stdout
```

3. **Ensure your wallet is ready:**

```bash
mkdir -p ~/.joinmarket-ng/wallets
# Create or copy your mnemonic file to ~/.joinmarket-ng/wallets/maker.mnemonic
```

4. **Update RPC credentials** in `docker-compose.yml` (change `rpcuser`/`rpcpassword`).

5. **Start the maker:**

```bash
docker-compose up -d
```

> **Note**: Initial Bitcoin Core sync can take several hours to days depending on hardware.

### Using Neutrino Instead of Bitcoin Core

If you cannot run a full node, Neutrino is available as a lightweight alternative.
Be aware this limits compatibility with takers.

Replace the `bitcoind` service with `neutrino` and update maker environment:

```yaml
environment:
  - BACKEND_TYPE=neutrino
  - NEUTRINO_URL=http://neutrino:8334

# Replace bitcoind service with:
neutrino:
  image: ghcr.io/m0wer/neutrino-api
  environment:
    - NETWORK=mainnet
  volumes:
    - neutrino-data:/data/neutrino
```

### Customizing Fees

Edit the environment section in `docker-compose.yml`:

```yaml
environment:
  # Relative fee (0.1% - default)
  - CJ_FEE_RELATIVE=0.001
  # OR absolute fee (uncomment one, not both)
  # - CJ_FEE_ABSOLUTE=1000
  - MIN_SIZE=100000
```

### Viewing Logs

```bash
docker-compose logs -f maker
```

## Environment Variables

### Required

| Variable | Default | Description |
|----------|---------|-------------|
| `MNEMONIC_FILE` | - | Path to encrypted mnemonic file (recommended) |
| `MNEMONIC` | - | Direct mnemonic phrase (not recommended for production) |

### Tor Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TOR_SOCKS_HOST` | `127.0.0.1` | Tor SOCKS proxy host |
| `TOR_SOCKS_PORT` | `9050` | Tor SOCKS proxy port |
| `TOR_CONTROL_HOST` | Auto-detect | Tor control host (auto-detects from `TOR_SOCKS_HOST` in Docker) |
| `TOR_CONTROL_PORT` | `9051` | Tor control port |
| `TOR_COOKIE_PATH` | Auto-detect | Path to Tor cookie auth file |

### Backend Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_TYPE` | `full_node` | Backend type: `full_node` or `neutrino` |
| `BITCOIN_RPC_URL` | `http://localhost:8332` | Bitcoin Core RPC URL (full_node only) |
| `BITCOIN_RPC_USER` | - | Bitcoin Core RPC username (full_node only) |
| `BITCOIN_RPC_PASSWORD` | - | Bitcoin Core RPC password (full_node only) |
| `NEUTRINO_URL` | `http://localhost:8334` | Neutrino REST API URL (neutrino only) |

### Network Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK` | `mainnet` | Protocol network: `mainnet`, `testnet`, `signet`, `regtest` |
| `BITCOIN_NETWORK` | `$NETWORK` | Bitcoin network for address generation (if different from protocol network) |
| `DIRECTORY_SERVERS` | (network defaults) | Comma-separated list of directory servers (host:port) |

### Fee Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MIN_SIZE` | `100000` | Minimum CoinJoin size in sats |
| `CJ_FEE_RELATIVE` | `0.001` | Relative fee (0.001 = 0.1%) - auto-selects `sw0reloffer` type |
| `CJ_FEE_ABSOLUTE` | - | Absolute fee in sats - auto-selects `sw0absoffer` type if set |
| `TX_FEE_CONTRIBUTION` | `0` | Transaction fee contribution in sats |

> **Important:** Only set ONE of `CJ_FEE_RELATIVE` or `CJ_FEE_ABSOLUTE`. The offer type is automatically selected based on which you provide.

### Advanced Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FIDELITY_BOND_LOCKTIMES` | Auto-discover | Comma-separated Unix timestamps for fidelity bond locktimes |
| `MERGE_ALGORITHM` | `default` | UTXO selection: `default`, `gradual`, `greedy`, `random` |
| `ONION_SERVING_HOST` | `127.0.0.1` | Host to bind for incoming .onion connections |
| `ONION_SERVING_PORT` | `5222` | Port for incoming .onion connections |
| `JOINMARKET_DATA_DIR` | `~/.joinmarket-ng` | Data directory for history and blacklist |

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
| `--cj-fee-relative` | 0.001 | Relative fee (0.001 = 0.1%) - auto-selects sw0reloffer |
| `--cj-fee-absolute` | - | Absolute fee in sats - auto-selects sw0absoffer |
| `--min-size` | 100000 | Minimum CoinJoin size in sats |
| `--tor-control-host` | Auto-detect | Tor control port host |
| `--tor-control-port` | 9051 | Tor control port |
| `--tor-cookie-path` | Auto-detect | Path to Tor cookie auth file |
| `--disable-tor-control` | - | Disable ephemeral hidden service creation (NOT recommended) |

Use env vars for RPC credentials (see jmwallet README).

## Security

- Wallet files are encrypted - keep your password safe
- Bot verifies all transactions before signing
- All directory connections go through Tor
- Never expose your mnemonic or share wallet files
- File permissions automatically set to 600

### Spam Protection

The maker includes automatic rate limiting with exponential backoff to prevent orderbook spam attacks:

- **Normal**: 1 response per 10 seconds
- **After 10 violations**: Backoff to 60 seconds (moderate)
- **After 50 violations**: Backoff to 300 seconds (severe)
- **After 100 violations**: Peer banned for 1 hour

Thresholds are configurable via environment variables if needed (see config.py).

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
