FROM python:3.14-slim

WORKDIR /app

# Install system dependencies for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
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

# Install taker dependencies
COPY taker/pyproject.toml /app/taker/pyproject.toml
RUN pip install --no-cache-dir typer httpx loguru pydantic cryptography bech32 base58

# Copy taker source and install
COPY taker/src /app/taker/src
RUN pip install --no-cache-dir -e /app/taker

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

# CoinJoin settings
ENV COINJOIN_AMOUNT=1000000
ENV MIN_MAKERS=4
ENV MAX_CJ_FEE_REL=0.001
ENV MAX_CJ_FEE_ABS=5000

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

CMD ["jm-taker", "--help"]
