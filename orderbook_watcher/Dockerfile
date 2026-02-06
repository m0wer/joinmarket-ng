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
COPY jmcore/requirements.txt /build/jmcore/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user "/build/jmcore"

# Install orderbook_watcher dependencies
COPY orderbook_watcher/requirements.txt /build/orderbook_watcher/
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; fi && \
    pip install --no-cache-dir --user -r /build/orderbook_watcher/requirements.txt

# Copy source and static files, normalize permissions and timestamps for reproducibility
# This runs as root in builder, ensuring consistent 644/755 permissions regardless of source
# Timestamps are normalized to SOURCE_DATE_EPOCH because:
# - BuildKit's rewrite-timestamp only modifies the OCI tar output, not layer content hashes
# - Layer digests are computed BEFORE rewriting, so files must have identical timestamps
# - Without this, local files (old mtime) differ from CI (fresh git clone mtime)
COPY orderbook_watcher/src /build/orderbook_watcher/src
COPY orderbook_watcher/static /build/orderbook_watcher/static
RUN find /build/orderbook_watcher/src /build/orderbook_watcher/static -type f -exec chmod 644 {} + && \
    find /build/orderbook_watcher/src /build/orderbook_watcher/static -type d -exec chmod 755 {} + && \
    if [ -n "$SOURCE_DATE_EPOCH" ]; then \
        find /build/orderbook_watcher/src /build/orderbook_watcher/static -exec touch -d @${SOURCE_DATE_EPOCH} {} +; \
    fi

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

# Copy application source and static files from builder (with normalized permissions)
COPY --from=builder --chown=jm:jm /build/orderbook_watcher/src /app/orderbook_watcher/src
COPY --from=builder --chown=jm:jm /build/orderbook_watcher/static /app/orderbook_watcher/static

ENV PYTHONPATH=/app/orderbook_watcher/src

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

CMD ["python", "-m", "orderbook_watcher.main"]
