# JoinMarket Wallet Library (jmwallet)

Modern HD wallet for JoinMarket with support for Bitcoin Core nodes and lightweight Neutrino SPV.

## Installation

See [INSTALL.md](../INSTALL.md) for complete installation instructions including:
- Automated installation with `install.sh`
- Virtual environment setup
- Backend setup (Bitcoin Core or Neutrino)

**Quick install** (if you already have the repo):

```bash
cd joinmarket-ng
source jmvenv/bin/activate  # If you used install.sh
# OR create venv: python3 -m venv jmvenv && source jmvenv/bin/activate
cd jmwallet
pip install -e ../jmcore .
```

## Quick Start

### 1. Generate a Wallet

Create an encrypted wallet file with password protection:

```bash
mkdir -p ~/.joinmarket-ng/wallets
jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/wallet.mnemonic
```

**IMPORTANT**: The mnemonic is displayed once during generation. Write it down and store it securely offline - it's your only backup if you lose the encrypted file!

### 2. Choose Your Backend

#### Option A: Neutrino (Recommended for Beginners)

Lightweight SPV backend - no full node needed (~500MB vs ~500GB).

Start Neutrino server with Docker:

```bash
docker run -d \
  --name neutrino \
  -p 8334:8334 \
  -v neutrino-data:/data/neutrino \
  -e NETWORK=mainnet \
  -e LOG_LEVEL=info \
  ghcr.io/m0wer/neutrino-api
```

**Note**: Pre-built binaries are also available in the [m0wer/neutrino-api](https://github.com/m0wer/neutrino-api/releases) releases.

Check wallet balance:

```bash
jm-wallet info \
  --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic \
  --backend neutrino
```

#### Option B: Bitcoin Core Full Node

For maximum security and privacy. Requires a synced Bitcoin Core node (v23+).

Create an environment file to avoid exposing credentials in shell history:

```bash
cat > ~/.joinmarket-ng/bitcoin.env << EOF
export BITCOIN_RPC_URL=http://127.0.0.1:8332
export BITCOIN_RPC_USER=your_rpc_user
export BITCOIN_RPC_PASSWORD=your_rpc_password
EOF
chmod 600 ~/.joinmarket-ng/bitcoin.env
```

Load environment and check balance:

```bash
source ~/.joinmarket-ng/bitcoin.env
jm-wallet info \
  --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic \
  --backend full_node
```

### 3. View Your Addresses

The wallet info command displays your balance across 5 mixdepths:

```
Total Balance: 10,500,000 sats (0.10500000 BTC)

Balance by mixdepth:
  Mixdepth 0:       5,000,000 sats  |  bc1q...
  Mixdepth 1:       3,000,000 sats  |  bc1q...
  Mixdepth 2:       2,500,000 sats  |  bc1q...
  Mixdepth 3:               0 sats  |  bc1q...
  Mixdepth 4:               0 sats  |  bc1q...
```

**Privacy Note**: Never merge coins across mixdepths outside of CoinJoin!

## CLI Commands

### Generate Wallet

```bash
# Generate and save encrypted wallet (RECOMMENDED)
jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/wallet.mnemonic

# Just generate (display only, not saved)
jm-wallet generate

# 12-word mnemonic instead of 24
jm-wallet generate --words 12 --save --prompt-password --output ~/.joinmarket-ng/wallets/wallet.mnemonic
```

**Note**: `--prompt-password` only works with `--save`. The wallet file is encrypted and requires the password to use.

### View Balance

```bash
# Neutrino backend (default ports)
jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic --backend neutrino

# Bitcoin Core (with environment file)
source ~/.joinmarket-ng/bitcoin.env
jm-wallet info --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic --backend full_node
```

### List Fidelity Bonds

```bash
jm-wallet list-bonds --mnemonic-file ~/.joinmarket-ng/wallets/wallet.mnemonic
```

### All Commands

For detailed help on any command, see the auto-generated help sections below.

<!-- AUTO-GENERATED HELP START: jm-wallet -->

<details>
<summary><code>jm-wallet --help</code></summary>

```

 Usage: jm-wallet [OPTIONS] COMMAND [ARGS]...

 JoinMarket Wallet Management

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ generate                Generate a new BIP39 mnemonic phrase with secure     │
│                         entropy.                                             │
│ info                    Display wallet information and balances by mixdepth. │
│ list-bonds              List all fidelity bonds in the wallet.               │
│ generate-bond-address   Generate a fidelity bond (timelocked P2WSH) address. │
│ send                    Send a simple transaction from wallet to an address. │
│ history                 View CoinJoin transaction history.                   │
│ validate                Validate a BIP39 mnemonic phrase.                    │
│ registry-list           List all fidelity bonds in the registry.             │
│ registry-show           Show detailed information about a specific fidelity  │
│                         bond.                                                │
│ recover-bonds           Recover fidelity bonds by scanning all 960 possible  │
│                         timelocks.                                           │
│ registry-sync           Sync fidelity bond funding status from the           │
│                         blockchain.                                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet generate --help</code></summary>

```

 Usage: jm-wallet generate [OPTIONS]

 Generate a new BIP39 mnemonic phrase with secure entropy.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --words            -w      INTEGER  Number of words (12, 15, 18, 21, or 24)  │
│                                     [default: 24]                            │
│ --save             -s               Save to file                             │
│ --output           -o      PATH     Output file path                         │
│ --password         -p      TEXT     Password for encryption                  │
│ --prompt-password                   Prompt for password interactively        │
│ --help                              Show this message and exit.              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet info --help</code></summary>

```

 Usage: jm-wallet info [OPTIONS]

 Display wallet information and balances by mixdepth.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic                         TEXT     BIP39 mnemonic                   │
│ --mnemonic-file            -f      PATH     Path to mnemonic file            │
│ --password                 -p      TEXT     Password for encrypted file      │
│ --bip39-passphrase                 TEXT     BIP39 passphrase (13th/25th      │
│                                             word)                            │
│                                             [env var: BIP39_PASSPHRASE]      │
│ --prompt-bip39-passphrase                   Prompt for BIP39 passphrase      │
│                                             interactively                    │
│ --network                  -n      TEXT     Bitcoin network                  │
│                                             [default: mainnet]               │
│ --backend                  -b      TEXT     Backend: full_node | neutrino    │
│                                             [default: full_node]             │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│                                             [default: http://127.0.0.1:8332] │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --neutrino-url                     TEXT     [env var: NEUTRINO_URL]          │
│                                             [default: http://127.0.0.1:8334] │
│ --extended                 -e               Show detailed address view with  │
│                                             derivations                      │
│ --gap                      -g      INTEGER  Max address gap to show in       │
│                                             extended view                    │
│                                             [default: 6]                     │
│ --data-dir                         PATH     Data directory (default:         │
│                                             ~/.joinmarket-ng or              │
│                                             $JOINMARKET_DATA_DIR)            │
│ --log-level                -l      TEXT     [default: INFO]                  │
│ --help                                      Show this message and exit.      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet list-bonds --help</code></summary>

```

 Usage: jm-wallet list-bonds [OPTIONS]

 List all fidelity bonds in the wallet.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic                         TEXT                                      │
│ --mnemonic-file            -f      PATH                                      │
│ --password                 -p      TEXT                                      │
│ --bip39-passphrase                 TEXT     BIP39 passphrase (13th/25th      │
│                                             word)                            │
│                                             [env var: BIP39_PASSPHRASE]      │
│ --prompt-bip39-passphrase                   Prompt for BIP39 passphrase      │
│ --network                  -n      TEXT     [default: mainnet]               │
│ --backend                  -b      TEXT     [default: full_node]             │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│                                             [default: http://127.0.0.1:8332] │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --locktime                 -L      INTEGER  Locktime(s) to scan for          │
│ --log-level                -l      TEXT     [default: INFO]                  │
│ --help                                      Show this message and exit.      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet generate-bond-address --help</code></summary>

```

 Usage: jm-wallet generate-bond-address [OPTIONS]

 Generate a fidelity bond (timelocked P2WSH) address.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic                         TEXT                                      │
│ --mnemonic-file            -f      PATH                                      │
│ --password                 -p      TEXT                                      │
│ --bip39-passphrase                 TEXT     BIP39 passphrase (13th/25th      │
│                                             word)                            │
│                                             [env var: BIP39_PASSPHRASE]      │
│ --prompt-bip39-passphrase                   Prompt for BIP39 passphrase      │
│ --locktime                 -L      INTEGER  Locktime as Unix timestamp       │
│                                             [default: 0]                     │
│ --locktime-date            -d      TEXT     Locktime as YYYY-MM (must be 1st │
│                                             of month)                        │
│ --index                    -i      INTEGER  Address index [default: 0]       │
│ --network                  -n      TEXT     [default: mainnet]               │
│ --data-dir                         PATH     Data directory (default:         │
│                                             ~/.joinmarket-ng or              │
│                                             $JOINMARKET_DATA_DIR)            │
│ --no-save                                   Do not save the bond to the      │
│                                             registry                         │
│ --log-level                -l      TEXT     [default: INFO]                  │
│ --help                                      Show this message and exit.      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet send --help</code></summary>

```

 Usage: jm-wallet send [OPTIONS] DESTINATION

 Send a simple transaction from wallet to an address.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    destination      TEXT  Destination address [required]                   │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --amount                   -a      INTEGER  Amount in sats (0 for sweep)     │
│                                             [default: 0]                     │
│ --mnemonic                         TEXT                                      │
│ --mnemonic-file            -f      PATH                                      │
│ --password                 -p      TEXT                                      │
│ --bip39-passphrase                 TEXT     BIP39 passphrase (13th/25th      │
│                                             word)                            │
│                                             [env var: BIP39_PASSPHRASE]      │
│ --prompt-bip39-passphrase                   Prompt for BIP39 passphrase      │
│ --mixdepth                 -m      INTEGER  Source mixdepth [default: 0]     │
│ --fee-rate                         FLOAT    Manual fee rate in sat/vB (e.g.  │
│                                             1.5). Mutually exclusive with    │
│                                             --block-target. Defaults to      │
│                                             3-block estimation.              │
│ --block-target                     INTEGER  Target blocks for fee estimation │
│                                             (1-1008). Defaults to 3.         │
│ --network                  -n      TEXT     [default: mainnet]               │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│                                             [default: http://127.0.0.1:8332] │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --broadcast                                 Broadcast the transaction        │
│                                             [default: True]                  │
│ --yes                      -y               Skip confirmation prompt         │
│ --log-level                -l      TEXT     [default: INFO]                  │
│ --help                                      Show this message and exit.      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet history --help</code></summary>

```

 Usage: jm-wallet history [OPTIONS]

 View CoinJoin transaction history.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --limit     -n      INTEGER  Max entries to show                             │
│ --role      -r      TEXT     Filter by role (maker/taker)                    │
│ --stats     -s               Show statistics only                            │
│ --csv                        Output as CSV                                   │
│ --data-dir          PATH     Data directory (default: ~/.joinmarket-ng or    │
│                              $JOINMARKET_DATA_DIR)                           │
│ --help                       Show this message and exit.                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet validate --help</code></summary>

```

 Usage: jm-wallet validate [OPTIONS] [MNEMONIC_ARG]

 Validate a BIP39 mnemonic phrase.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│   mnemonic_arg      [MNEMONIC_ARG]  Mnemonic to validate                     │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic-file  -f      PATH  Path to mnemonic file                         │
│ --password       -p      TEXT                                                │
│ --help                         Show this message and exit.                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet registry-list --help</code></summary>

```

 Usage: jm-wallet registry-list [OPTIONS]

 List all fidelity bonds in the registry.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --data-dir             PATH  Data directory (default: ~/.joinmarket-ng or    │
│                              $JOINMARKET_DATA_DIR)                           │
│ --funded-only  -f            Show only funded bonds                          │
│ --active-only  -a            Show only active (funded & not expired) bonds   │
│ --json         -j            Output as JSON                                  │
│ --log-level    -l      TEXT  [default: WARNING]                              │
│ --help                       Show this message and exit.                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet registry-show --help</code></summary>

```

 Usage: jm-wallet registry-show [OPTIONS] ADDRESS

 Show detailed information about a specific fidelity bond.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    address      TEXT  Bond address to show [required]                      │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --data-dir           PATH  Data directory (default: ~/.joinmarket-ng or      │
│                            $JOINMARKET_DATA_DIR)                             │
│ --json       -j            Output as JSON                                    │
│ --log-level  -l      TEXT  [default: WARNING]                                │
│ --help                     Show this message and exit.                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet recover-bonds --help</code></summary>

```

 Usage: jm-wallet recover-bonds [OPTIONS]

 Recover fidelity bonds by scanning all 960 possible timelocks.

 This command scans the blockchain for fidelity bonds at all valid timenumber
 locktimes (Jan 2020 through Dec 2099). Use this when recovering a wallet from
 mnemonic and you don't know which locktimes were used for fidelity bonds.
 The scan checks address index 0 by default (most wallets only use index 0).
 Use --max-index to scan more addresses per locktime if needed.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic                         TEXT                                      │
│ --mnemonic-file            -f      PATH                                      │
│ --password                 -p      TEXT                                      │
│ --bip39-passphrase                 TEXT     BIP39 passphrase (13th/25th      │
│                                             word)                            │
│                                             [env var: BIP39_PASSPHRASE]      │
│ --prompt-bip39-passphrase                   Prompt for BIP39 passphrase      │
│ --network                  -n      TEXT     [default: mainnet]               │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│                                             [default: http://127.0.0.1:8332] │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --max-index                -i      INTEGER  Max address index per locktime   │
│                                             to scan (default 1)              │
│                                             [default: 1]                     │
│ --data-dir                         PATH     Data directory (default:         │
│                                             ~/.joinmarket-ng or              │
│                                             $JOINMARKET_DATA_DIR)            │
│ --log-level                -l      TEXT     [default: INFO]                  │
│ --help                                      Show this message and exit.      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary><code>jm-wallet registry-sync --help</code></summary>

```

 Usage: jm-wallet registry-sync [OPTIONS]

 Sync fidelity bond funding status from the blockchain.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --mnemonic                         TEXT                                      │
│ --mnemonic-file            -f      PATH                                      │
│ --password                 -p      TEXT                                      │
│ --bip39-passphrase                 TEXT  BIP39 passphrase (13th/25th word)   │
│                                          [env var: BIP39_PASSPHRASE]         │
│ --prompt-bip39-passphrase                Prompt for BIP39 passphrase         │
│ --network                  -n      TEXT  [default: mainnet]                  │
│ --rpc-url                          TEXT  [env var: BITCOIN_RPC_URL]          │
│                                          [default: http://127.0.0.1:8332]    │
│ --rpc-user                         TEXT  [env var: BITCOIN_RPC_USER]         │
│ --rpc-password                     TEXT  [env var: BITCOIN_RPC_PASSWORD]     │
│ --data-dir                         PATH  Data directory (default:            │
│                                          ~/.joinmarket-ng or                 │
│                                          $JOINMARKET_DATA_DIR)               │
│ --log-level                -l      TEXT  [default: INFO]                     │
│ --help                                   Show this message and exit.         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>


<!-- AUTO-GENERATED HELP END: jm-wallet -->
