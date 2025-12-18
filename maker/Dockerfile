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

# Install jmwallet dependencies
COPY jmwallet/pyproject.toml /app/jmwallet/pyproject.toml
COPY jmwallet/src /app/jmwallet/src
RUN pip install --no-cache-dir -e /app/jmwallet

# Install maker dependencies
COPY maker/pyproject.toml /app/maker/pyproject.toml
RUN pip install --no-cache-dir typer httpx loguru pydantic cryptography

# Copy maker source and install
COPY maker/src /app/maker/src
RUN pip install --no-cache-dir -e /app/maker

# Create non-root user
RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

# Environment variables
ENV NETWORK=mainnet
# Bitcoin network for address generation (bcrt1 vs tb1 vs bc1)
# Defaults to NETWORK if not set
ENV BITCOIN_NETWORK=
ENV LOG_LEVEL=INFO
ENV MIN_SIZE=100000
ENV TX_FEE_CONTRIBUTION=1000
ENV CJ_FEE_RELATIVE=0.0002
ENV CJ_FEE_ABSOLUTE=500
ENV OFFER_TYPE=sw0reloffer
ENV BACKEND_TYPE=bitcoin_core

# Tor settings (for connecting to directory servers)
ENV TOR_SOCKS_HOST=127.0.0.1
ENV TOR_SOCKS_PORT=9050

# Bitcoin Core RPC (when using bitcoin_core backend)
ENV BITCOIN_RPC_URL=http://localhost:8332
ENV BITCOIN_RPC_USER=
ENV BITCOIN_RPC_PASSWORD=

# Neutrino settings (when using neutrino backend)
ENV NEUTRINO_URL=http://localhost:8334

# Directory servers (comma-separated list of host:port)
ENV DIRECTORY_SERVERS=

# Wallet mnemonic (REQUIRED - set at runtime!)
# ENV MNEMONIC=

# Use shell to conditionally add --bitcoin-network if set
CMD ["sh", "-c", "\
    BITCOIN_NETWORK_ARG=\"\"; \
    if [ -n \"${BITCOIN_NETWORK}\" ]; then \
        BITCOIN_NETWORK_ARG=\"--bitcoin-network ${BITCOIN_NETWORK}\"; \
    fi; \
    jm-maker start \
    --mnemonic \"${MNEMONIC}\" \
    --network \"${NETWORK}\" \
    ${BITCOIN_NETWORK_ARG} \
    --backend-type \"${BACKEND_TYPE}\" \
    --rpc-url \"${BITCOIN_RPC_URL}\" \
    --rpc-user \"${BITCOIN_RPC_USER}\" \
    --rpc-password \"${BITCOIN_RPC_PASSWORD}\" \
    --neutrino-url \"${NEUTRINO_URL}\" \
    --min-size \"${MIN_SIZE}\" \
    --cj-fee-relative \"${CJ_FEE_RELATIVE}\" \
    --tx-fee-contribution \"${TX_FEE_CONTRIBUTION}\" \
    --directory-servers \"${DIRECTORY_SERVERS}\""]
