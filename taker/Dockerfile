# =============================================================================
# Builder stage: Install dependencies and build wheels
# =============================================================================
# Base image digests for reproducible builds
# Update with: ./scripts/update-base-images.sh
ARG PYTHON_VERSION=3.14
ARG PYTHON_SLIM_DIGEST=sha256:fa0acdcd760f0bf265bc2c1ee6120776c4d92a9c3a37289e17b9642ad2e5b83b

FROM python:${PYTHON_VERSION}-slim@${PYTHON_SLIM_DIGEST} AS builder

WORKDIR /build

# Install build dependencies (sorted alphabetically for reproducibility)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libffi-dev \
    libsodium-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Reproducible builds: SOURCE_DATE_EPOCH must be set via --build-arg for reproducible builds
# When not provided, pip install runs without it (non-reproducible but works)
# Usage: docker build --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) ...
ARG SOURCE_DATE_EPOCH

# Install jmcore dependencies (with hash verification)
COPY jmcore/requirements.txt /build/jmcore/requirements.txt
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user "/build/jmcore"

# Install jmwallet dependencies
COPY jmwallet/requirements.txt /build/jmwallet/requirements.txt
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/jmwallet/requirements.txt

# Copy jmwallet source and install
COPY jmwallet/pyproject.toml /build/jmwallet/pyproject.toml
COPY jmwallet/src /build/jmwallet/src
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user /build/jmwallet

# Install taker dependencies
COPY taker/requirements.txt /build/taker/requirements.txt
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/taker/requirements.txt

# Copy taker source and install
COPY taker/src /build/taker/src
COPY taker/pyproject.toml /build/taker/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user /build/taker

# =============================================================================
# Production stage: Minimal runtime image
# =============================================================================
FROM python:${PYTHON_VERSION}-slim@${PYTHON_SLIM_DIGEST} AS production

WORKDIR /app

# Install only runtime dependencies (no build tools)
# Delete apt/dpkg logs and ldconfig cache for reproducible builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/log/dpkg.log /var/log/apt/* \
    && rm -rf /var/cache/ldconfig/aux-cache

# Reproducible builds: SOURCE_DATE_EPOCH for consistent timestamps
ARG SOURCE_DATE_EPOCH

# Create non-root user with reproducible shadow entry
# useradd sets "last password change" to current day, breaking reproducibility
# We fix it by calculating days since epoch from SOURCE_DATE_EPOCH
RUN useradd -m -u 1000 jm && \
    if [ -n "$SOURCE_DATE_EPOCH" ]; then \
        DAYS_SINCE_EPOCH=$((SOURCE_DATE_EPOCH / 86400)) && \
        sed -i "s/^jm:!:[0-9]*:/jm:!:${DAYS_SINCE_EPOCH}:/" /etc/shadow; \
    fi

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

# Data directory for JoinMarket files (commitment blacklist, history)
# Users can override this with -e JOINMARKET_DATA_DIR=/custom/path
ENV JOINMARKET_DATA_DIR=/home/jm/.joinmarket-ng

CMD ["jm-taker", "--help"]
