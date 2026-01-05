# JoinMarket-NG Installation Guide

This guide walks you through installing JoinMarket-NG on Linux, macOS, and Raspberry Pi devices.

## System Requirements

- **Python**: 3.11 or higher (3.14 recommended)
- **Operating System**: Linux, macOS, or Raspberry Pi OS
- **Disk Space**: ~100MB for the software, plus blockchain backend storage
- **Network**: Internet connection (Tor will be configured automatically)

## Quick Installation (Recommended)

The fastest way to get started is using the automated installation script:

### 1. Install System Dependencies

Before installing JoinMarket-NG, you need to install some system packages required for building Python dependencies:

**Debian/Ubuntu/Raspberry Pi OS:**
```bash
sudo apt update
sudo apt install -y git build-essential libffi-dev libsodium-dev pkg-config python3 python3-venv python3-pip
```

**macOS:**
```bash
brew install libsodium pkg-config python3
```

These packages are needed for:
- `git`: Version control (required to clone the repository)
- `build-essential` / Xcode Command Line Tools: C compiler and build tools
- `libffi-dev`: Foreign Function Interface library (for cryptography)
- `libsodium-dev` / `libsodium`: Cryptographic library
- `pkg-config`: Helper tool for compiling (required by coincurve)
- `python3-venv`: Python virtual environment support

### 2. Clone the Repository

```bash
git clone https://github.com/m0wer/joinmarket-ng.git
cd joinmarket-ng
```

### 3. Run the Installer

```bash
./install.sh
```

The script will:
- Check for required system dependencies
- Check Python version (3.11+ required)
- Create a Python virtual environment at `jmvenv/`
- Install all dependencies for core components
- Optionally install maker, taker, or both
- Set up the basic directory structure

**Note**: You can run `./install.sh` multiple times safely. If you accidentally exit the script (e.g., with Ctrl+C), simply run it again to resume or change your component selection.

### 4. Activate the Environment

After installation completes:

```bash
source jmvenv/bin/activate
```

You're now ready to use JoinMarket-NG! Jump to the [Next Steps](#next-steps) section.

## Manual Installation

If you prefer to install manually or the script doesn't work on your system:

### 1. Install System Dependencies

**Debian/Ubuntu/Raspberry Pi OS:**
```bash
sudo apt update
sudo apt install -y git build-essential libffi-dev libsodium-dev pkg-config python3 python3-venv python3-pip
```

**macOS:**
```bash
brew install libsodium pkg-config python3
```

### 2. Clone the Repository

```bash
git clone https://github.com/m0wer/joinmarket-ng.git
cd joinmarket-ng
```

### 3. Create Virtual Environment

Python 3.11+ uses externally-managed environments by default, so you need to create a virtual environment:

```bash
python3 -m venv jmvenv
source jmvenv/bin/activate
```

**Note**: You'll need to run `source jmvenv/bin/activate` every time you open a new terminal to use JoinMarket-NG.

### 4. Install Core Libraries

Install the foundational libraries first:

```bash
# Install jmcore (shared library)
cd jmcore
pip install -e .
cd ..

# Install jmwallet (wallet library)
cd jmwallet
pip install -e .
cd ..
```

### 5. Install Components

Choose which components you want to install:

#### For Makers (Earn Fees)

```bash
cd maker
pip install -e .
cd ..
```

#### For Takers (Mix Your Coins)

```bash
cd taker
pip install -e .
cd ..
```

#### For Developers

```bash
# Install development dependencies for testing
cd jmcore
pip install -r requirements-dev.txt
cd ../jmwallet
pip install -r requirements-dev.txt
cd ../maker  # or taker
pip install -r requirements-dev.txt
cd ..
```

## Raspberry Pi Specific Notes

### Installing Python 3.11+

Raspberry Pi OS Lite may come with an older Python version. To install Python 3.11:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
python3 --version  # Check version
```

If the version is below 3.11, you may need to install from source or use a PPA:

```bash
# For Ubuntu/Debian-based systems
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv
```

Then use `python3.11` instead of `python3` when creating the virtual environment.

### Memory Considerations

Raspberry Pi 4 with 4GB+ RAM is recommended. For devices with less RAM:
- Use Neutrino backend instead of Bitcoin Core (see [Backend Setup](#backend-setup))
- Consider running Bitcoin Core on a separate device and connecting via RPC

## Backend Setup

JoinMarket-NG requires a Bitcoin blockchain backend. Choose one:

### Option A: Bitcoin Core (Full Node)

**Pros**: Maximum privacy, trustlessness, and compatibility
**Cons**: ~600GB disk space, several days to sync

1. Install Bitcoin Core (v23+) from https://bitcoincore.org/en/download/
2. Configure `bitcoin.conf`:

```conf
# Enable RPC
server=1
rpcuser=yourusername
rpcpassword=yourpassword
rpcport=8332

# Optional: Reduce bandwidth
maxconnections=8
```

3. Start Bitcoin Core and wait for sync
4. Test connection: `bitcoin-cli getblockchaininfo`

### Option B: Neutrino (Light Client)

**Pros**: ~500MB disk space, syncs in minutes
**Cons**: Less privacy than full node, makers have limited compatibility

1. Install Docker (if not already installed):

```bash
# Linux
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Verify
docker --version
```

2. Run Neutrino server:

```bash
docker run -d \
  --name neutrino \
  --restart unless-stopped \
  -p 8334:8334 \
  -v neutrino-data:/data/neutrino \
  -e NETWORK=mainnet \
  -e LOG_LEVEL=info \
  ghcr.io/m0wer/neutrino-api
```

Alternatively, download pre-built binaries from [m0wer/neutrino-api releases](https://github.com/m0wer/neutrino-api/releases).

## Tor Setup

JoinMarket-NG requires Tor for privacy. Installation varies by component:

### For Takers and Orderbook Watchers

Only SOCKS proxy needed (default Tor installation):

```bash
# Linux (Debian/Ubuntu)
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor

# macOS
brew install tor
brew services start tor
```

Verify Tor is running: `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`

### For Makers

Makers need control port access to create ephemeral hidden services:

1. Edit `/etc/tor/torrc` (or `$(brew --prefix)/etc/tor/torrc` on macOS):

```conf
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

2. Restart Tor:

```bash
# Linux
sudo systemctl restart tor

# macOS
brew services restart tor
```

3. Verify control port: `nc -z 127.0.0.1 9051 && echo "Control port accessible"`

**Raspberry Pi Note**: Default Tor package works fine, just edit `/etc/tor/torrc` as above.

## Next Steps

Now that installation is complete:

### For Makers

Read the [Maker Quick Start](./maker/README.md#quick-start) to:
1. Create a wallet
2. Fund it with bitcoin
3. Start earning fees

### For Takers

Read the [Taker Quick Start](./taker/README.md#quick-start) to:
1. Create a wallet
2. Fund it with bitcoin
3. Execute your first CoinJoin

### For Developers

See [DOCS.md](./DOCS.md) for architecture details and [component READMEs](./README.md#component-documentation) for development setup.

## Troubleshooting

### "Could NOT find PkgConfig" or "CMake configuration failed"

This error occurs when installing dependencies like `coincurve`. You need to install system build dependencies first:

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt update
sudo apt install -y git build-essential libffi-dev libsodium-dev pkg-config python3-venv

# macOS
brew install libsodium pkg-config
```

After installing these packages, try the installation again.

### "python3: command not found"

Install Python first:

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt install python3

# macOS
brew install python3
```

### "pip: command not found"

Install pip or use the `ensurepip` module:

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt install python3-pip

# Or use ensurepip
python3 -m ensurepip
```

### "error: externally-managed-environment" or "No module named 'venv'"

You need to install the `python3-venv` package:

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt install python3-venv
```

Then create the virtual environment:

```bash
python3 -m venv jmvenv
source jmvenv/bin/activate
```

### "Permission denied" When Installing

Don't use `sudo` with pip inside a virtual environment. If you see permission errors:

1. Make sure you activated the virtual environment: `source jmvenv/bin/activate`
2. Your prompt should show `(jmvenv)` at the beginning

### Virtual Environment Not Activating

Make sure you're in the `joinmarket-ng` directory:

```bash
cd joinmarket-ng
source jmvenv/bin/activate
```

### Installation Takes a Long Time or Times Out

Some dependencies like `coincurve` need to be compiled from source, which can take a few minutes on slower systems like Raspberry Pi. This is normal. If it fails, make sure all system dependencies are installed (see the "Could NOT find PkgConfig" section above).

### Installation Script Fails

First, check if system dependencies are installed:

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt update
sudo apt install -y git build-essential libffi-dev libsodium-dev pkg-config python3-venv

# macOS
brew install libsodium pkg-config
```

If the script was interrupted (e.g., with Ctrl+C), you can simply run it again:

```bash
./install.sh
```

The script is safe to run multiple times and will let you change your component selection.

If the issue persists, try manual installation (see [Manual Installation](#manual-installation) section above).

## Updating

To update to the latest version:

```bash
cd joinmarket-ng
source jmvenv/bin/activate

# Pull latest changes
git pull

# Update dependencies (re-run install script or manual steps)
./install.sh
# OR manually:
cd jmcore && pip install -e . && cd ..
cd jmwallet && pip install -e . && cd ..
cd maker && pip install -e . && cd ..  # if using maker
cd taker && pip install -e . && cd ..  # if using taker
```

## Uninstalling

To completely remove JoinMarket-NG:

```bash
cd joinmarket-ng

# Deactivate virtual environment if active
deactivate

# Remove virtual environment
rm -rf jmvenv/

# Optionally remove data directory (contains wallets!)
# rm -rf ~/.joinmarket-ng/

# Remove repository
cd ..
rm -rf joinmarket-ng/
```

**Warning**: The data directory `~/.joinmarket-ng/` contains your wallets. Make sure you have backups of your mnemonics before deleting!

## Getting Help

- **Documentation**: [README.md](./README.md) and [DOCS.md](./DOCS.md)
- **Component Guides**: See individual component READMEs in their directories
- **Community Support**:
  - Telegram: https://t.me/joinmarketorg
  - SimpleX: https://smp12.simplex.im/g#bx_0bFdk7OnttE0jlytSd73jGjCcHy2qCrhmEzgWXTk
