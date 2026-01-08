# JoinMarket-NG Installation Guide

This guide walks you through installing JoinMarket-NG on Linux, macOS, and Raspberry Pi devices.

## System Requirements

- **Python**: 3.11 or higher (3.14 recommended)
- **Operating System**: Linux, macOS, or Raspberry Pi OS
- **Disk Space**: ~100MB for the software, plus blockchain backend storage
- **Network**: Internet connection (Tor will be installed and configured automatically by the installer)

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
- **Install and configure Tor automatically** (asks for confirmation)
  - Installs Tor if not present
  - Configures localhost-only SOCKS proxy (127.0.0.1:9050)
  - Configures localhost-only control port (127.0.0.1:9051) for maker bots
  - Creates backup of existing Tor configuration
  - Restarts Tor service automatically
- Check Python version (3.11+ required)
- Create a Python virtual environment at `jmvenv/`
- Install all dependencies for core components
- Optionally install maker, taker, or both
- Set up the basic directory structure

**Note**: You can run `./install.sh` multiple times safely. If you accidentally exit the script (e.g., with Ctrl+C), simply run it again to resume or change your component selection.

**Skip Tor Setup**: If you want to configure Tor manually later, use `./install.sh --skip-tor`

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

JoinMarket-NG requires Tor for privacy and anonymity. The installation script (`./install.sh`) will **automatically install and configure Tor** for you with localhost-only bindings for security.

### Automated Setup (Recommended)

When you run `./install.sh`, it will:

1. **Detect and install Tor** if not already present
   - Linux: Uses `apt install tor`
   - macOS: Uses `brew install tor`

2. **Configure Tor** with localhost-only bindings:
   ```conf
   # SOCKS proxy for clients (bound to localhost only)
   SocksPort 127.0.0.1:9050

   # Control port for maker bots (localhost only)
   ControlPort 127.0.0.1:9051
   CookieAuthentication 1
   ```

3. **Restart Tor** and verify connectivity

4. **Create backups** of existing configuration before making changes

The automated setup ensures:
- **Security**: All ports bound to localhost (127.0.0.1) only, not accessible from network
- **Compatibility**: Works for all JoinMarket components (makers, takers, orderbook watchers)
- **Safety**: Backs up existing configuration before modifications

### Manual Setup

If you prefer manual installation or used `./install.sh --skip-tor`, follow these steps:

#### Install Tor

**Linux (Debian/Ubuntu/Raspberry Pi OS):**
```bash
sudo apt update
sudo apt install -y tor
```

**macOS:**
```bash
brew install tor
```

#### Configure Tor

Edit the Tor configuration file:
- **Linux**: `/etc/tor/torrc`
- **macOS**: `$(brew --prefix)/etc/tor/torrc` (usually `/opt/homebrew/etc/tor/torrc`)

Add the following configuration (localhost-only):

```conf
## JoinMarket Configuration
# SOCKS proxy for clients (bound to localhost only)
SocksPort 127.0.0.1:9050

# Control port for maker bots to create ephemeral hidden services (localhost only)
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

**Security Note**: The configuration above binds all ports to `127.0.0.1` (localhost only), meaning they are NOT accessible from the network. This is the recommended secure configuration for local development and production use.

#### Start Tor

**Linux:**
```bash
sudo systemctl start tor
sudo systemctl enable tor  # Start on boot
```

**macOS:**
```bash
brew services start tor
```

#### Verify Setup

Test SOCKS proxy (works for all components):
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

Test control port (needed for makers):
```bash
nc -z 127.0.0.1 9051 && echo "Control port accessible"
```

### Configuration Details

#### For Takers and Orderbook Watchers

Only SOCKS proxy access needed:
- **SOCKS Host**: 127.0.0.1
- **SOCKS Port**: 9050

This is automatically detected by default in JoinMarket-NG.

#### For Makers and Directory Servers

Require both SOCKS proxy and control port:
- **SOCKS Host**: 127.0.0.1
- **SOCKS Port**: 9050
- **Control Port Host**: 127.0.0.1
- **Control Port**: 9051
- **Authentication**: Cookie-based (CookieAuthentication 1)

Makers use the control port to create **ephemeral hidden services** dynamically at startup, allowing them to be reachable via .onion addresses without pre-configuring hidden services in torrc.

### Docker Environments

The automated setup configures Tor for localhost access. For Docker deployments, see the test configurations in `tests/e2e/reference/tor/conf/torrc` for examples of network-accessible configurations (binding to 0.0.0.0).

**Warning**: Only bind to 0.0.0.0 in isolated Docker networks. For local installations, always use 127.0.0.1.

### Troubleshooting

**"Could not connect to Tor SOCKS proxy"**
- Verify Tor is running: `systemctl status tor` (Linux) or `brew services list` (macOS)
- Check SOCKS port is accessible: `nc -z 127.0.0.1 9050`

**"Could not authenticate to Tor control port"**
- Ensure CookieAuthentication is enabled in torrc
- Check cookie file permissions: `/var/lib/tor/control_auth_cookie` (Linux) or `/var/run/tor/control.authcookie` (macOS)
- You may need to add your user to the `debian-tor` group (Linux): `sudo usermod -a -G debian-tor $USER`

**"Control port not accessible"**
- Verify ControlPort is configured in torrc
- Restart Tor after configuration changes
- Check port is listening: `nc -z 127.0.0.1 9051`

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
