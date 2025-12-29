FROM python:3.14-slim

WORKDIR /app

# Install system dependencies for cryptography and libnacl
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libsodium23 \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install jmcore dependencies first (cached layer)
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source and install
COPY jmcore/src /app/jmcore/src
COPY jmcore/pyproject.toml /app/jmcore/
RUN pip install --no-cache-dir -e /app/jmcore

# Install jmwallet dependencies and source
COPY jmwallet/requirements.txt /app/jmwallet/requirements.txt
RUN pip install --no-cache-dir -r /app/jmwallet/requirements.txt
COPY jmwallet/pyproject.toml /app/jmwallet/pyproject.toml
COPY jmwallet/src /app/jmwallet/src
RUN pip install --no-cache-dir -e /app/jmwallet

# Install taker dependencies
COPY taker/requirements.txt /app/taker/requirements.txt
RUN pip install --no-cache-dir -r /app/taker/requirements.txt

# Copy taker source and install
COPY taker/src /app/taker/src
COPY taker/pyproject.toml /app/taker/
RUN pip install --no-cache-dir -e /app/taker

# Create non-root user
RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

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
