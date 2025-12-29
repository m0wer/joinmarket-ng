FROM python:3.14-slim

WORKDIR /app

# Install system dependencies for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libsodium-dev \
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

# Install maker dependencies
COPY maker/requirements.txt /app/maker/requirements.txt
RUN pip install --no-cache-dir -r /app/maker/requirements.txt

# Copy maker source and install
COPY maker/src /app/maker/src
COPY maker/pyproject.toml /app/maker/
RUN pip install --no-cache-dir -e /app/maker

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
ENV MIN_SIZE=100000
ENV TX_FEE_CONTRIBUTION=1000

# CoinJoin fee - set ONE of these (they are mutually exclusive):
# CJ_FEE_RELATIVE: Percentage fee (e.g., 0.0002 = 0.02%)
# CJ_FEE_ABSOLUTE: Fixed satoshi amount (e.g., 500)
# If neither is set, defaults to CJ_FEE_RELATIVE=0.001 (0.1%)
ENV CJ_FEE_RELATIVE=
ENV CJ_FEE_ABSOLUTE=

ENV BACKEND_TYPE=full_node

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

# Fidelity bond locktimes (comma-separated list of Unix timestamps)
# These are used to scan for timelocked fidelity bond UTXOs
ENV FIDELITY_BOND_LOCKTIMES=

# Wallet mnemonic - one of MNEMONIC or MNEMONIC_FILE is required
# MNEMONIC: Direct mnemonic phrase (not recommended for production)
# MNEMONIC_FILE: Path to mnemonic file (recommended - mount as volume)
# ENV MNEMONIC=
# ENV MNEMONIC_FILE=/wallets/maker.mnemonic

# Enable sensitive logging (descriptors, addresses) for debugging
# WARNING: Do not enable in production - exposes wallet information
ENV SENSITIVE_LOGGING=

# Data directory for JoinMarket files (commitment blacklist, history)
# Set to /home/jm/.joinmarket-ng to use the volume mount
ENV JOINMARKET_DATA_DIR=/home/jm/.joinmarket-ng

# Use shell to conditionally add optional arguments
CMD ["sh", "-c", "\
    BITCOIN_NETWORK_ARG=\"\"; \
    if [ -n \"${BITCOIN_NETWORK}\" ]; then \
        BITCOIN_NETWORK_ARG=\"--bitcoin-network ${BITCOIN_NETWORK}\"; \
    fi; \
    FIDELITY_BOND_ARGS=\"\"; \
    if [ -n \"${FIDELITY_BOND_LOCKTIMES}\" ]; then \
        for lt in $(echo \"${FIDELITY_BOND_LOCKTIMES}\" | tr ',' ' '); do \
            FIDELITY_BOND_ARGS=\"${FIDELITY_BOND_ARGS} --fidelity-bond-locktime ${lt}\"; \
        done; \
    fi; \
    MNEMONIC_ARG=\"\"; \
    if [ -n \"${MNEMONIC_FILE}\" ]; then \
        MNEMONIC_ARG=\"--mnemonic-file ${MNEMONIC_FILE}\"; \
    fi; \
    DIRECTORY_ARG=\"\"; \
    if [ -n \"${DIRECTORY_SERVERS}\" ]; then \
        DIRECTORY_ARG=\"--directory-servers ${DIRECTORY_SERVERS}\"; \
    fi; \
    FEE_ARG=\"\"; \
    if [ -n \"${CJ_FEE_ABSOLUTE}\" ]; then \
        FEE_ARG=\"--cj-fee-absolute ${CJ_FEE_ABSOLUTE}\"; \
    elif [ -n \"${CJ_FEE_RELATIVE}\" ]; then \
        FEE_ARG=\"--cj-fee-relative ${CJ_FEE_RELATIVE}\"; \
    fi; \
    jm-maker start \
    ${MNEMONIC_ARG} \
    --network \"${NETWORK}\" \
    ${BITCOIN_NETWORK_ARG} \
    --backend-type \"${BACKEND_TYPE}\" \
    --rpc-url \"${BITCOIN_RPC_URL}\" \
    --rpc-user \"${BITCOIN_RPC_USER}\" \
    --rpc-password \"${BITCOIN_RPC_PASSWORD}\" \
    --neutrino-url \"${NEUTRINO_URL}\" \
    --min-size \"${MIN_SIZE}\" \
    ${FEE_ARG} \
    --tx-fee-contribution \"${TX_FEE_CONTRIBUTION}\" \
    ${DIRECTORY_ARG} \
    ${FIDELITY_BOND_ARGS}"]
