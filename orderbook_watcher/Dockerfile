# =============================================================================
# Builder stage: Install dependencies and build wheels
# =============================================================================
FROM python:3.14-slim AS builder

# Reproducible builds: Use SOURCE_DATE_EPOCH for consistent timestamps
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /build

# Install build dependencies (sorted alphabetically for reproducibility)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libffi-dev \
    libsodium-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install jmcore dependencies
COPY jmcore/requirements.txt /build/jmcore/
RUN pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN pip install --no-cache-dir --user "/build/jmcore"

# Install orderbook_watcher dependencies
COPY orderbook_watcher/requirements.txt /build/orderbook_watcher/
RUN pip install --no-cache-dir --user -r /build/orderbook_watcher/requirements.txt

# =============================================================================
# Production stage: Minimal runtime image
# =============================================================================
FROM python:3.14-slim AS production

# Reproducible builds: Use SOURCE_DATE_EPOCH for consistent timestamps
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

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

# Copy application source and static files (as jm user)
COPY --chown=jm:jm orderbook_watcher/src /app/orderbook_watcher/src
COPY --chown=jm:jm orderbook_watcher/static /app/orderbook_watcher/static

ENV PYTHONPATH=/app/orderbook_watcher/src

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

CMD ["python", "-m", "orderbook_watcher.main"]
