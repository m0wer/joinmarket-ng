# =============================================================================
# Builder stage: Install dependencies and build wheels
# =============================================================================
FROM python:3.14-slim AS builder

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
# Note: SOURCE_DATE_EPOCH is passed as ARG, which is available during RUN commands
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

# Install maker dependencies
COPY maker/requirements.txt /build/maker/requirements.txt
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/maker/requirements.txt

# Copy maker source and install
COPY maker/src /build/maker/src
COPY maker/pyproject.toml /build/maker/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user /build/maker

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

# Data directory for JoinMarket files (commitment blacklist, history)
# Users can override this with -e JOINMARKET_DATA_DIR=/custom/path
ENV JOINMARKET_DATA_DIR=/home/jm/.joinmarket-ng

CMD ["jm-maker", "--help"]
