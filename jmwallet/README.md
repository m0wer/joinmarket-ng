# JoinMarket Wallet Library (jmwallet)

Modern HD wallet for JoinMarket with support for Bitcoin Core nodes and lightweight Neutrino SPV.

## Installation

```bash
cd jmwallet
pip install -e .
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

```bash
jm-wallet --help
jm-wallet generate --help
jm-wallet info --help
jm-wallet list-bonds --help
jm-wallet generate-bond-address --help
jm-wallet generate-hot-keypair --help
jm-wallet prepare-certificate-message --help
jm-wallet import-certificate --help
```

## Cold Wallet Fidelity Bonds

For maximum security, fidelity bonds can use a certificate chain that keeps the bond UTXO private key completely offline in a hardware wallet:

### Workflow

1. **Generate bond address** (can be done on cold wallet or using watch-only):
   ```bash
   jm-wallet generate-bond-address \
     --mnemonic-file wallet.enc \
     --password "..." \
     --locktime-date "2026-01-01" \
     --index 0
   ```
   Fund this address with Bitcoin to create the bond.

2. **Generate hot wallet keypair** (on online machine):
   ```bash
   jm-wallet generate-hot-keypair
   ```
   Save both the private and public keys securely.

3. **Prepare certificate message** (on online machine - NO private keys needed):
   ```bash
   jm-wallet prepare-certificate-message <bond_address> \
     --cert-pubkey <hot_pubkey_from_step_2> \
     --cert-expiry-blocks 104832
   ```
   This outputs the message to sign. **IMPORTANT**: This does NOT require your cold wallet mnemonic.

4. **Sign with hardware wallet** (using Sparrow or similar):
   - Open Sparrow Wallet and connect your hardware wallet
   - Find the bond address (P2WSH timelocked address)
   - Use "Sign Message" and paste the message from step 3
   - Copy the signature (hex format)

5. **Import certificate** (on online machine):
   ```bash
   jm-wallet import-certificate <bond_address> \
     --cert-pubkey <hot_pubkey_from_step_2> \
     --cert-privkey <hot_privkey_from_step_2> \
     --cert-signature <signature_from_hardware_wallet> \
     --cert-expiry 52
   ```

6. **Run maker** - it will automatically use the certificate.

### Security Benefits

- **Hardware wallet security**: Bond UTXO private key NEVER leaves the hardware wallet
- **No mnemonic exposure**: Online tools never see your cold wallet mnemonic or private keys
- **Time-limited**: Certificate expires after ~2 years (configurable)
- **Revocable**: If hot wallet is compromised, only the certificate is at risk, not the bond funds
- **Renewable**: Sign a new message when the certificate expires

See [DOCS.md § Cold Wallet Setup](../DOCS.md#cold-wallet-setup) for detailed documentation.

## Features

- BIP32/BIP39/BIP84 HD wallet implementation
- 5 mixdepth isolation for privacy
- P2WPKH native segwit addresses (bc1...)
- Multi-backend: Bitcoin Core RPC or Neutrino SPV
- No BerkeleyDB dependency (works with Bitcoin Core v23+)
- Encrypted mnemonic storage

## Wallet Structure

JoinMarket uses mixdepths for privacy isolation:

- **Mixdepth 0-4**: Separate balance pools
- **Branches per mixdepth**:
  - Branch 0: External (receive) addresses
  - Branch 1: Internal (change) addresses
  - Branch 2: Fidelity bonds (time-locked)

## Security Notes

- Mnemonic files are encrypted with Fernet (symmetric encryption)
- Files automatically get restrictive permissions (`chmod 600`)
- Use `.env` files for RPC credentials instead of command-line args
- Never commit mnemonics or `.env` files to version control

## Using with Maker/Taker Bots

The `jm-wallet` CLI is for wallet management only. For CoinJoin operations:

1. Generate wallet: `jm-wallet generate --save --prompt-password`
2. Fund addresses: Send Bitcoin to mixdepth addresses
3. Run bots: Use `jm-maker` or `jm-taker` with same wallet file

## Advanced: Python API

For programmatic access:

```python
import asyncio
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig
from jmwallet.wallet.service import WalletService

async def main():
    config = NeutrinoConfig(base_url="http://localhost:8334", network="mainnet")
    backend = NeutrinoBackend(config)

    wallet = WalletService(
        mnemonic="your mnemonic phrase here",
        backend=backend,
        network="mainnet",
    )

    await wallet.sync_all()
    balance = await wallet.get_total_balance()
    print(f"Balance: {balance:,} sats")

asyncio.run(main())
```

See code documentation for full API details.
