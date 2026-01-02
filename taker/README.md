# JoinMarket Taker Client

Mix your bitcoin for privacy via CoinJoin. Takers initiate transactions and pay small fees to makers.

## Installation

```bash
pip install -e ../jmcore ../jmwallet .
```

## Quick Start

### 1. Create a Wallet

Generate an encrypted wallet file:

```bash
mkdir -p ~/.joinmarket-ng/wallets
jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/taker.mnemonic
```

**IMPORTANT**: Write down the displayed mnemonic - it's your only backup!

See [jmwallet README](../jmwallet/README.md) for wallet management details.

### 2. Check Balance & Get Deposit Address

```bash
# View balance and addresses
jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic --backend neutrino
```

### 3. Fund Your Wallet

Send bitcoin to one of the displayed addresses.

### 4. Execute a CoinJoin

#### Option A: Bitcoin Core Full Node (Recommended)

For maximum trustlessness and privacy. Create an environment file to avoid credentials in shell history:

```bash
cat > ~/.joinmarket-ng/bitcoin.env << EOF
export BITCOIN_RPC_URL=http://127.0.0.1:8332
export BITCOIN_RPC_USER=your_rpc_user
export BITCOIN_RPC_PASSWORD=your_rpc_password
EOF
chmod 600 ~/.joinmarket-ng/bitcoin.env
```

Execute CoinJoin:

```bash
source ~/.joinmarket-ng/bitcoin.env
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 1000000 \
  --backend full_node
```

#### Option B: Neutrino Backend

Lightweight alternative if you cannot run a full node.

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

Mix to next mixdepth (recommended for privacy):

```bash
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 1000000 \
  --backend neutrino
```

This mixes 1,000,000 sats (0.01 BTC) to the next mixdepth in your wallet.

## Common Use Cases

### Mix Within Your Wallet

Default behavior - sends to next mixdepth (INTERNAL):

```bash
jm-taker coinjoin --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic --amount 500000
```

### Send to External Address

Mix and send to a specific address:

```bash
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 500000 \
  --destination bc1qexampleaddress...
```

### Sweep Entire Mixdepth

Use `--amount 0` to sweep all funds from a mixdepth:

```bash
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 0 \
  --mixdepth 2
```

### Enhanced Privacy (More Makers)

More counterparties = better privacy:

```bash
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 1000000 \
  --counterparties 6
```

## Tumbler (Automated Mixing)

For maximum privacy, use the tumbler to execute multiple CoinJoins over time.

### Create Schedule

Save as `schedule.json`:

```json
{
  "entries": [
    {
      "mixdepth": 0,
      "amount": 500000,
      "counterparty_count": 4,
      "destination": "INTERNAL",
      "wait_time": 300
    },
    {
      "mixdepth": 1,
      "amount": 0,
      "counterparty_count": 5,
      "destination": "bc1qfinaladdress...",
      "wait_time": 0
    }
  ]
}
```

**Fields**:
- `amount`: Sats (integer), fraction 0-1 (float), or 0 (sweep all)
- `destination`: Bitcoin address or "INTERNAL" for next mixdepth
- `wait_time`: Seconds to wait after this CoinJoin

### Run Tumbler

```bash
jm-taker tumble schedule.json --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic
```

## Configuration

### Default Settings

Sensible defaults for most users:
- **Destination**: INTERNAL (next mixdepth)
- **Counterparties**: 3 makers
- **Max absolute fee**: 500 sats per maker
- **Max relative fee**: 0.1% (0.001)

### Custom Fee Limits

Lower fees (may find fewer makers):

```bash
jm-taker coinjoin \
  --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic \
  --amount 1000000 \
  --max-abs-fee 200 \
  --max-rel-fee 0.0005
```

## Docker Deployment

A production-ready `docker-compose.yml` is provided in this directory with:

- **Bitcoin Core backend** for maximum trustlessness and privacy
- **Tor** for privacy (SOCKS proxy only - takers don't need control port)
- **Logging limits** to prevent disk exhaustion from log flooding
- **Resource limits** for CPU and memory
- **Health checks** for service dependencies

### Quick Start

1. **Create Tor configuration directory:**

```bash
mkdir -p tor/conf tor/data tor/run
```

2. **Create `tor/conf/torrc`:**

```torc
SocksPort 0.0.0.0:9050
DataDirectory /var/lib/tor
Log notice stdout
```

3. **Ensure your wallet is ready:**

```bash
mkdir -p ~/.joinmarket-ng/wallets
# Create or copy your mnemonic file to ~/.joinmarket-ng/wallets/taker.mnemonic
```

4. **Update RPC credentials** in `docker-compose.yml` (change `rpcuser`/`rpcpassword`).

5. **Start Bitcoin Core and Tor:**

```bash
docker-compose up -d bitcoind tor
```

> **Note**: Initial Bitcoin Core sync can take several hours to days depending on hardware.

6. **Run a CoinJoin:**

```bash
docker-compose run --rm taker jm-taker coinjoin --amount 1000000
```

### Running the Tumbler

```bash
# Create schedule file
cat > ~/.joinmarket-ng/schedule.json << 'EOF'
{
  "entries": [
    {"mixdepth": 0, "amount": 500000, "counterparty_count": 4, "destination": "INTERNAL", "wait_time": 300},
    {"mixdepth": 1, "amount": 0, "counterparty_count": 5, "destination": "INTERNAL", "wait_time": 0}
  ]
}
EOF

# Run tumbler
docker-compose run --rm taker jm-taker tumble /home/jm/.joinmarket-ng/schedule.json
```

### Using Neutrino Instead of Bitcoin Core

If you cannot run a full node, Neutrino is available as a lightweight alternative.

Replace the `bitcoind` service with `neutrino` and update taker environment:

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

### Viewing Logs

```bash
docker-compose logs -f taker
```

Note: Takers only need Tor SOCKS proxy (port 9050) - they don't serve a hidden service, so no control port is needed.

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
| `COINJOIN_AMOUNT` | `1000000` | Default CoinJoin amount in sats |
| `MIN_MAKERS` | `4` | Minimum number of makers |
| `MAX_CJ_FEE_REL` | `0.001` | Maximum relative fee (0.1%) |
| `MAX_CJ_FEE_ABS` | `5000` | Maximum absolute fee in sats |
| `TOR_SOCKS_HOST` | `127.0.0.1` | Tor SOCKS proxy host |
| `TOR_SOCKS_PORT` | `9050` | Tor SOCKS proxy port |
| `SENSITIVE_LOGGING` | - | Enable sensitive logging (set to `1` or `true`) |

## CLI Reference

```bash
# Execute single CoinJoin
jm-taker coinjoin [OPTIONS]

# Run tumbler schedule
jm-taker tumble SCHEDULE_FILE [OPTIONS]

# See all options
jm-taker coinjoin --help
jm-taker tumble --help
```

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `--amount` | (required) | Amount in sats, 0 for sweep |
| `--destination` | INTERNAL | Address or INTERNAL for next mixdepth |
| `--mixdepth` | 0 | Source mixdepth (0-4) |
| `--counterparties` | 3 | Number of makers (more = better privacy) |
| `--backend` | full_node | Backend: full_node or neutrino |
| `--max-abs-fee` | 500 | Max absolute fee per maker (sats) |
| `--max-rel-fee` | 0.001 | Max relative fee (0.1%) |

Use env vars for RPC credentials (see jmwallet README).

## Privacy Tips

1. **Use INTERNAL destination**: Keeps funds in your wallet across mixdepths
2. **Multiple CoinJoins**: Use tumbler for enhanced privacy over time
3. **More counterparties**: `--counterparties 6` increases anonymity set
4. **Avoid round amounts**: Makes your output harder to identify
5. **Wait between mixes**: Add `wait_time` in tumbler schedules
6. **All via Tor**: Directory connections automatically use Tor

## Security

- Wallet files are encrypted - keep your password safe
- Transactions verified before signing
- PoDLE commitments prevent sybil attacks
- All directory connections via Tor
- Never expose your mnemonic or share wallet files

## Troubleshooting

**"No suitable makers found"**
- Check directory server connectivity
- Lower fee limits if too strict
- Try during peak hours

**"PoDLE commitment failed"**
- Need 5+ confirmations on UTXOs
- UTXO must be ≥20% of CoinJoin amount

**"Insufficient balance"**
- Check: `jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/taker.mnemonic`
- Reserve some balance for fees

**"CoinJoin timeout"**
- Try fewer counterparties
- Network might be slow
