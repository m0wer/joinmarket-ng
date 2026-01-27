# JoinMarket-NG Installation Guide

This guide walks you through installing JoinMarket-NG on Linux, macOS, and Raspberry Pi devices.

## System Requirements

- **Python**: 3.11 or higher (3.14 recommended)
- **Operating System**: Linux, macOS, or Raspberry Pi OS
- **Disk Space**: ~100MB for the software, plus blockchain backend storage
- **Network**: Internet connection (Tor will be installed and configured automatically by the installer)

## Quick Installation (Recommended)

The easiest way to install JoinMarket-NG is with a single command:

```bash
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash
```

The installer will:
- Check and install system dependencies (asks for confirmation)
- Install and configure Tor for privacy
- Create a Python virtual environment at `~/.joinmarket-ng/venv/`
- Install JoinMarket-NG from the latest release (both maker and taker by default)
- Create a configuration file at `~/.joinmarket-ng/config.toml`
- Add shell integration for easy activation

### Installation Options

```bash
# Install both maker and taker (default)
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash

# Install maker only
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --maker

# Install taker only
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --taker

# Install specific version
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --version 0.9.0

# Skip Tor setup (configure manually later)
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --skip-tor
```

### After Installation

Start a new terminal or run:

```bash
source ~/.joinmarket-ng/activate.sh
```

You're now ready to use JoinMarket-NG! Jump to the [Configuration](#configuration) section.

## Updating

To update to the latest version:

```bash
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --update
```

Or update to a specific version:

```bash
curl -sSL https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh | bash -s -- --update --version 0.9.0
```

**Note**: After updating, restart any running maker/taker processes.

## Manual Installation (For Developers)

If you prefer to install from source for development:

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

### 2. Clone and Install

```bash
git clone https://github.com/m0wer/joinmarket-ng.git
cd joinmarket-ng

# Create virtual environment
python3 -m venv jmvenv
source jmvenv/bin/activate

# Install in development mode (editable)
cd jmcore && pip install -e . && cd ..
cd jmwallet && pip install -e . && cd ..
cd maker && pip install -e . && cd ..  # if using maker
cd taker && pip install -e . && cd ..  # if using taker
```

### 3. Install Development Dependencies

```bash
cd jmcore && pip install -r requirements-dev.txt && cd ..
cd jmwallet && pip install -r requirements-dev.txt && cd ..
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
5. Configure JoinMarket-NG (see [Configuration](#configuration) below)

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

3. Configure JoinMarket-NG (see [Configuration](#configuration) below)

## Configuration

JoinMarket-NG uses a TOML configuration file at `~/.joinmarket-ng/config.toml`. The installer creates this file automatically with all settings commented out, showing defaults.

### Configuring Your Backend

Edit the config file to match your setup:

```bash
nano ~/.joinmarket-ng/config.toml
```

**For Neutrino (Light Client):**

```toml
[bitcoin]
backend_type = "neutrino"
neutrino_url = "http://127.0.0.1:8334"
```

**For Bitcoin Core (Full Node):**

```toml
[bitcoin]
backend_type = "descriptor_wallet"
rpc_url = "http://127.0.0.1:8332"
rpc_user = "your_rpc_user"
rpc_password = "your_rpc_password"
```

### Common Settings

```toml
[network]
network = "mainnet"  # mainnet, testnet, signet, regtest

[tor]
socks_host = "127.0.0.1"
socks_port = 9050

[maker]
cj_fee_relative = 0.001  # 0.1% fee
min_size = 100000        # Minimum 100k sats

[taker]
counterparty_count = 3   # Number of makers per CoinJoin
```

### Configuration Priority

Settings are loaded in this order (highest priority first):
1. CLI arguments (e.g., `--backend neutrino`)
2. Environment variables (e.g., `BITCOIN__RPC_URL`)
3. Config file (`~/.joinmarket-ng/config.toml`)
4. Default values

This allows you to override settings temporarily via CLI without modifying the config file.

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

### DoS Defense for Hidden Services (Makers)

JoinMarket-NG supports Tor-level DoS protection for hidden services, but **the available protections depend on your Tor version and hidden service type**.

#### Ephemeral Hidden Services (JoinMarket-NG default)

When using ephemeral hidden services (created via ADD_ONION), DoS protection is limited:

- **PoW Defense via ADD_ONION**: Requires **Tor 0.4.9.2+** (not yet in stable releases as of early 2026)
- **Introduction Point Rate Limiting**: **NOT supported** for ephemeral services (Tor protocol limitation)

Most current Tor installations (0.4.8.x) do **not** support PoW defense for ephemeral hidden services. JoinMarket-NG will log a warning and create the service without PoW protection in this case.

#### Persistent Hidden Services (Recommended for DoS Protection)

For **full DoS protection**, use persistent hidden services defined in torrc. This is recommended for makers running the **reference implementation** or anyone experiencing DoS attacks:

```conf
# Maker hidden service
HiddenServiceDir /var/lib/tor/maker_hs
HiddenServiceVersion 3
HiddenServicePort 8765 127.0.0.1:8765

## Introduction Point DoS Defense (Tor 0.4.2+)
# Rate limit connection attempts at introduction points
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceEnableIntroDoSRatePerSec 25
HiddenServiceEnableIntroDoSBurstPerSec 200

## Proof-of-Work Defense (Tor 0.4.8+ with --enable-gpl build)
# Clients solve computational puzzles to connect; effort auto-scales under attack
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 250
HiddenServicePoWQueueBurst 2500
```

**Version Summary:**
| Feature | Ephemeral HS (ADD_ONION) | Persistent HS (torrc) |
|---------|-------------------------|----------------------|
| Intro Point Rate Limiting | Not supported | Tor 0.4.2+ |
| PoW Defense | Tor 0.4.9.2+ | Tor 0.4.8+ (with --enable-gpl) |

**Notes:**
- PoW defense requires Tor built with `--enable-gpl` flag; check with `tor --version`
- Older Tor versions without PoW support will ignore those lines gracefully
- Reference: https://community.torproject.org/onion-services/advanced/dos/

### Docker Environments

The automated setup configures Tor for localhost access. For Docker deployments, see the test configurations in `tests/e2e/reference/tor/conf/torrc` for examples of network-accessible configurations (binding to 0.0.0.0).

**Warning**: Only bind to 0.0.0.0 in isolated Docker networks. For local installations, always use 127.0.0.1.

### Troubleshooting

**"Could not connect to Tor SOCKS proxy"**
- Verify Tor is running: `systemctl status tor` (Linux) or `brew services list` (macOS)
- Check SOCKS port is accessible: `nc -z 127.0.0.1 9050`

**"Could not authenticate to Tor control port"**
- Ensure CookieAuthentication is enabled in torrc
- Check cookie file permissions: `/run/tor/control.authcookie` (Linux) or `/var/run/tor/control.authcookie` (macOS)
- You may need to add your user to the `debian-tor` group (Linux): `sudo usermod -a -G debian-tor $USER`

**"Control port not accessible"**
- Verify ControlPort is configured in torrc
- Restart Tor after configuration changes
- Check port is listening: `nc -z 127.0.0.1 9051`

## Next Steps

Now that installation is complete:

### 1. Configure Your Backend

Edit `~/.joinmarket-ng/config.toml` to configure your Bitcoin backend (see [Configuration](#configuration) above).

### 2. Create a Wallet

```bash
mkdir -p ~/.joinmarket-ng/wallets
jm-wallet generate --save --prompt-password --output ~/.joinmarket-ng/wallets/wallet.mnemonic
```

**IMPORTANT**: Write down the displayed mnemonic - it's your only backup!

### 3. Start Using JoinMarket

**For Makers** (earn fees by providing liquidity):

```bash
jm-maker start -f ~/.joinmarket-ng/wallets/wallet.mnemonic
```

See [maker/README.md](./maker/README.md) for detailed maker configuration.

**For Takers** (mix your coins for privacy):

```bash
jm-taker coinjoin -f ~/.joinmarket-ng/wallets/wallet.mnemonic --amount 1000000
```

See [taker/README.md](./taker/README.md) for detailed taker options.

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

### Installation Takes a Long Time or Times Out

Some dependencies like `coincurve` need to be compiled from source, which can take a few minutes on slower systems like Raspberry Pi. This is normal.

### curl Command Not Working (curl | bash)

If piping to bash doesn't work, download and run manually:

```bash
curl -o install.sh https://raw.githubusercontent.com/m0wer/joinmarket-ng/master/install.sh
chmod +x install.sh
./install.sh
```

## Uninstalling

To completely remove JoinMarket-NG:

```bash
# Remove virtual environment
rm -rf ~/.joinmarket-ng/venv/

# Optionally remove data directory (contains wallets!)
# rm -rf ~/.joinmarket-ng/

# Remove shell integration from ~/.bashrc or ~/.zshrc if added
```

**Warning**: The data directory `~/.joinmarket-ng/` contains your wallets. Make sure you have backups of your mnemonics before deleting!

## Docker Deployment

For advanced users, Docker Compose files are provided in the `maker/` and `taker/` directories. These are useful for:
- Running in isolated environments
- Production deployments
- Testing

To use Docker:

```bash
# Clone the repository
git clone https://github.com/m0wer/joinmarket-ng.git
cd joinmarket-ng

# Start maker with Docker
cd maker
docker-compose up -d

# Or taker
cd ../taker
docker-compose up -d
```

See the respective README files for Docker-specific configuration.

## Getting Help

- **Documentation**: [README.md](./README.md) and [DOCS.md](./DOCS.md)
- **Component Guides**: See individual component READMEs in their directories
- **Community Support**:
  - Telegram: https://t.me/joinmarketorg
  - SimpleX: https://smp12.simplex.im/g#bx_0bFdk7OnttE0jlytSd73jGjCcHy2qCrhmEzgWXTk
