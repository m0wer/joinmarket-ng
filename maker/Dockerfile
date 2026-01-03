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

# Copy jmcore source and install
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN pip install --no-cache-dir --user /build/jmcore

# Install jmwallet dependencies
COPY jmwallet/requirements.txt /build/jmwallet/requirements.txt
RUN pip install --no-cache-dir --user -r /build/jmwallet/requirements.txt

# Copy jmwallet source and install
COPY jmwallet/pyproject.toml /build/jmwallet/pyproject.toml
COPY jmwallet/src /build/jmwallet/src
RUN pip install --no-cache-dir --user /build/jmwallet

# Install maker dependencies
COPY maker/requirements.txt /build/maker/requirements.txt
RUN pip install --no-cache-dir --user -r /build/maker/requirements.txt

# Copy maker source and install
COPY maker/src /build/maker/src
COPY maker/pyproject.toml /build/maker/
RUN pip install --no-cache-dir --user /build/maker

# =============================================================================
# Production stage: Minimal runtime image
# =============================================================================
FROM python:3.14-slim AS production

WORKDIR /app

# Install only runtime dependencies (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts are in PATH
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN useradd -m -u 1000 jm

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
