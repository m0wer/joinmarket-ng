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
# Generate with defaults (saves to ~/.joinmarket-ng/wallets/default.mnemonic with password)
jm-wallet generate

# Or specify a custom location
jm-wallet generate --output ~/.joinmarket-ng/wallets/my-wallet.mnemonic

# Generate without saving (display only)
jm-wallet generate --no-save --no-prompt-password
```

**IMPORTANT**: The mnemonic is displayed once during generation. Write it down and store it securely offline - it's your only backup if you lose the encrypted file!

**Note**: By default, the wallet is saved and password-protected. Use `--no-save` to skip saving or `--no-prompt-password` to skip password protection (not recommended for production).

### 2. Choose Your Backend

JoinMarket NG supports three blockchain backends with different trade-offs:

#### Option A: Descriptor Wallet (Recommended - Fast & Efficient)

**Best for**: Running a maker bot or frequent operations with your own Bitcoin Core node.

Uses Bitcoin Core's descriptor wallet feature to persistently track your addresses. After one-time setup, syncs are nearly instant using `listunspent` instead of scanning the entire UTXO set.

**Performance**: ~1 second per sync (vs ~90 seconds with scantxoutset)

**Requirements**: Bitcoin Core v24+ with your own node

**Security Note**: ⚠️ **Never use with a third-party node!** Your wallet addresses are stored in Bitcoin Core's wallet files. Funds are safe, but your addresses and balances are visible to whoever controls the node.

Create an environment file:

```bash
cat > ~/.joinmarket-ng/bitcoin.env << EOF
export BITCOIN__RPC_URL=http://127.0.0.1:8332
export BITCOIN__RPC_USER=your_rpc_user
export BITCOIN__RPC_PASSWORD=your_rpc_password
EOF
chmod 600 ~/.joinmarket-ng/bitcoin.env
```

Check wallet balance (first run will import descriptors):

```bash
source ~/.joinmarket-ng/bitcoin.env
jm-wallet info \
  --mnemonic-file ~/.joinmarket-ng/wallets/my-wallet.mnemonic \
  --backend descriptor_wallet

# Or if using default wallet:
jm-wallet info --backend descriptor_wallet
```

The first run imports your wallet descriptors into Bitcoin Core (one-time ~5 second operation). Subsequent syncs are nearly instant.

#### Option B: Neutrino (Lightweight SPV)

**Best for**: Limited storage or fast initial sync.

Lightweight SPV backend using BIP157/158 compact block filters.

**Storage**: ~500 MB (vs ~900 GB for full node)

**Privacy**: High (downloads filters, not addresses)

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
  --mnemonic-file ~/.joinmarket-ng/wallets/my-wallet.mnemonic \
  --backend neutrino

# Or if using default wallet:
jm-wallet info --backend neutrino
```

#### Backend Comparison

| Feature | Descriptor Wallet | Full Node (Legacy) | Neutrino |
|---------|-------------------|-------------------|----------|
| **Sync Speed** | ~1s | ~90s | ~5s |
| **Storage** | ~900 GB | ~900 GB | ~500 MB |
| **Setup** | One-time import | None | External server |
| **Privacy** | High (own node) | High (own node) | High (filters) |
| **Mempool** | ✅ Yes | ✅ Yes | ❌ No |

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
# Generate and save encrypted wallet to default location (recommended)
jm-wallet generate

# Generate and save to custom location
jm-wallet generate --output ~/my-wallet.mnemonic

# Just display (not saved - for testing only)
jm-wallet generate --no-save --no-prompt-password

# 12-word mnemonic instead of 24
jm-wallet generate --words 12
```

**Note**:
- Default location: `~/.joinmarket-ng/wallets/default.mnemonic`
- By default, the wallet is saved and password-protected
- Use `--no-save` to skip saving, `--no-prompt-password` to skip encryption (not recommended)

### View Balance

```bash
# Using default wallet
jm-wallet info --backend neutrino

# Using specific wallet file
jm-wallet info --mnemonic-file ~/my-wallet.mnemonic --backend neutrino

# Bitcoin Core (with environment file)
source ~/.joinmarket-ng/bitcoin.env
jm-wallet info --backend descriptor_wallet
```

### List Fidelity Bonds

```bash
# Using default wallet
jm-wallet list-bonds

# Using specific wallet file
jm-wallet list-bonds --mnemonic-file ~/my-wallet.mnemonic
```

## Cold Wallet Fidelity Bonds

For maximum security, fidelity bonds can use a certificate chain that keeps the bond UTXO private key completely offline in a hardware wallet. The bond private key never touches any internet-connected device.

### Workflow

1. **Get public key from Sparrow Wallet**:
   - Open Sparrow Wallet with your hardware wallet
   - Go to Addresses tab
   - Find/create address at path `m/84'/0'/0'/2/0` (fidelity bond path)
   - Right-click the address and select "Copy Public Key"

2. **Create bond address** (online - NO private keys needed):
   ```bash
   jm-wallet create-bond-address <pubkey_from_step_1> \
     --locktime-date "2026-01"
   ```
   Fund this address with Bitcoin to create the bond.

3. **Generate hot wallet keypair** (on online machine):
   ```bash
   jm-wallet generate-hot-keypair
   ```
   Save both the private and public keys securely.

4. **Prepare certificate message** (online - NO private keys needed):
   ```bash
   jm-wallet prepare-certificate-message <bond_address> \
     --cert-pubkey <hot_pubkey_from_step_3> \
     --cert-expiry-blocks 104832
   ```

5. **Sign with hardware wallet** (using Sparrow):
   - Open Sparrow Wallet and connect your hardware wallet
   - Go to Tools -> Sign/Verify Message
   - Select the address matching your bond's public key
   - Paste the hex message from step 4
   - Sign and copy the signature

6. **Import certificate** (on online machine):
   ```bash
   jm-wallet import-certificate <bond_address> \
     --cert-pubkey <hot_pubkey_from_step_3> \
     --cert-privkey <hot_privkey_from_step_3> \
     --cert-signature <signature_from_hardware_wallet> \
     --cert-expiry 52
   ```

7. **Run maker** - it will automatically use the certificate.

### Security Benefits

- **Complete cold storage**: Bond private keys NEVER leave the hardware wallet
- **No mnemonic exposure**: No mnemonics or private keys needed on online systems
- **Public key only**: Bond address created from public key extracted from Sparrow
- **Time-limited**: Certificate expires after ~2 years (configurable)
- **Revocable**: If hot wallet is compromised, only the certificate is at risk, not the bond funds
- **Renewable**: Sign a new message when the certificate expires

See [DOCS.md](../DOCS.md) for detailed documentation.

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
│ --backend                  -b      TEXT     Backend: scantxoutset |          │
│                                             descriptor_wallet | neutrino     │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --neutrino-url                     TEXT     [env var: NEUTRINO_URL]          │
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
│ --network                  -n      TEXT     Bitcoin network                  │
│ --backend                  -b      TEXT     Backend: scantxoutset |          │
│                                             descriptor_wallet | neutrino     │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
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
│ --network                  -n      TEXT     Bitcoin network                  │
│ --backend                  -b      TEXT     Backend: scantxoutset |          │
│                                             descriptor_wallet | neutrino     │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --neutrino-url                     TEXT     [env var: NEUTRINO_URL]          │
│ --broadcast                                 Broadcast the transaction        │
│                                             [default: True]                  │
│ --yes                      -y               Skip confirmation prompt         │
│ --select-utxos             -s               Interactively select UTXOs       │
│                                             (fzf-like TUI)                   │
│ --data-dir                         PATH     Data directory (default:         │
│                                             ~/.joinmarket-ng or              │
│                                             $JOINMARKET_DATA_DIR)            │
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
│ --network                  -n      TEXT     Bitcoin network                  │
│ --backend                  -b      TEXT     Backend: scantxoutset |          │
│                                             descriptor_wallet | neutrino     │
│ --rpc-url                          TEXT     [env var: BITCOIN_RPC_URL]       │
│ --rpc-user                         TEXT     [env var: BITCOIN_RPC_USER]      │
│ --rpc-password                     TEXT     [env var: BITCOIN_RPC_PASSWORD]  │
│ --neutrino-url                     TEXT     [env var: NEUTRINO_URL]          │
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
│ --network                  -n      TEXT                                      │
│ --backend                  -b      TEXT  Backend: scantxoutset |             │
│                                          descriptor_wallet | neutrino        │
│ --rpc-url                          TEXT  [env var: BITCOIN_RPC_URL]          │
│ --rpc-user                         TEXT  [env var: BITCOIN_RPC_USER]         │
│ --rpc-password                     TEXT  [env var: BITCOIN_RPC_PASSWORD]     │
│ --neutrino-url                     TEXT  [env var: NEUTRINO_URL]             │
│ --data-dir                         PATH  Data directory (default:            │
│                                          ~/.joinmarket-ng or                 │
│                                          $JOINMARKET_DATA_DIR)               │
│ --log-level                -l      TEXT  [default: INFO]                     │
│ --help                                   Show this message and exit.         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>


<!-- AUTO-GENERATED HELP END: jm-wallet -->
