FROM python:3.14-slim

WORKDIR /app

# Install system dependencies for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
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
ENV LOG_LEVEL=INFO
ENV MIN_SIZE=100000
ENV TX_FEE_CONTRIBUTION=1000
ENV CJ_FEE_RELATIVE=0.0002
ENV CJ_FEE_ABSOLUTE=500
ENV OFFER_TYPE=sw0reloffer
ENV BACKEND_TYPE=mempool

# Tor settings (for connecting to directory servers)
ENV TOR_SOCKS_HOST=127.0.0.1
ENV TOR_SOCKS_PORT=9050

# Bitcoin Core RPC (when using bitcoin_core backend)
ENV BITCOIN_RPC_URL=http://localhost:8332
ENV BITCOIN_RPC_USER=
ENV BITCOIN_RPC_PASSWORD=

# Mempool API (when using mempool backend)
ENV MEMPOOL_API_URL=https://mempool.space/api

# Directory servers (comma-separated list of host:port)
ENV DIRECTORY_SERVERS=

# Wallet mnemonic (REQUIRED - set at runtime!)
# ENV MNEMONIC=

CMD ["jm-maker", "start"]
