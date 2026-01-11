# =============================================================================
# Builder stage: Install dependencies and build wheels
# =============================================================================
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libsodium-dev \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install jmcore dependencies
COPY jmcore/requirements.txt /build/jmcore/requirements.txt
RUN pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN pip install --no-cache-dir --user "/build/jmcore[notifications]"

# Install jmwallet dependencies
COPY jmwallet/requirements.txt /build/jmwallet/requirements.txt
RUN pip install --no-cache-dir --user -r /build/jmwallet/requirements.txt

# Copy jmwallet source and install
COPY jmwallet/pyproject.toml /build/jmwallet/pyproject.toml
COPY jmwallet/src /build/jmwallet/src
RUN pip install --no-cache-dir --user /build/jmwallet

# Install taker dependencies
COPY taker/requirements.txt /build/taker/requirements.txt
RUN pip install --no-cache-dir --user -r /build/taker/requirements.txt

# Copy taker source and install
COPY taker/src /build/taker/src
COPY taker/pyproject.toml /build/taker/
RUN pip install --no-cache-dir --user /build/taker

# =============================================================================
# Production stage: Minimal runtime image
# =============================================================================
FROM python:3.14-slim AS production

WORKDIR /app

# Install only runtime dependencies (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user first
RUN useradd -m -u 1000 jm

# Copy Python packages from builder and set ownership
COPY --from=builder --chown=jm:jm /root/.local /home/jm/.local

# Switch to non-root user
USER jm

# Make sure scripts are in PATH
ENV PATH=/home/jm/.local/bin:$PATH

# Create data directory for JoinMarket files
# This includes commitment blacklist, history, and other persistent data
RUN mkdir -p /home/jm/.joinmarket-ng && chmod 700 /home/jm/.joinmarket-ng

# Declare volume for persistent data
VOLUME /home/jm/.joinmarket-ng

# Environment variables
ENV NETWORK=mainnet
# Bitcoin network for address generation (bcrt1 vs tb1 vs bc1)
# Defaults to NETWORK if not set
ENV BITCOIN_NETWORK=
ENV LOG_LEVEL=INFO
ENV BACKEND_TYPE=full_node

# CoinJoin settings
ENV COINJOIN_AMOUNT=1000000
ENV MIN_MAKERS=4
ENV MAX_CJ_FEE_REL=0.001
ENV MAX_CJ_FEE_ABS=5000

# Tor settings (for connecting to directory servers)
ENV TOR_SOCKS_HOST=127.0.0.1
ENV TOR_SOCKS_PORT=9050

# Bitcoin Core RPC (when using full_node backend)
ENV BITCOIN_RPC_URL=http://localhost:8332
ENV BITCOIN_RPC_USER=
ENV BITCOIN_RPC_PASSWORD=

# Neutrino settings (when using neutrino backend)
ENV NEUTRINO_URL=http://localhost:8334

# Directory servers (comma-separated list of host:port)
# Leave empty to use default mainnet directory nodes
ENV DIRECTORY_SERVERS=

# Wallet mnemonic - one of MNEMONIC or MNEMONIC_FILE is required
# MNEMONIC: Direct mnemonic phrase (not recommended for production)
# MNEMONIC_FILE: Path to mnemonic file (recommended - mount as volume)
# ENV MNEMONIC=
# ENV MNEMONIC_FILE=/wallets/taker.mnemonic

# Enable sensitive logging (descriptors, addresses) for debugging
# WARNING: Do not enable in production - exposes wallet information
ENV SENSITIVE_LOGGING=

# Data directory for JoinMarket files (commitment blacklist, history)
# Set to /home/jm/.joinmarket-ng to use the volume mount
ENV JOINMARKET_DATA_DIR=/home/jm/.joinmarket-ng

CMD ["jm-taker", "--help"]
