# =============================================================================
# Builder stage: Install dependencies and build wheels
# =============================================================================
ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim AS builder

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
COPY jmcore/requirements.txt /build/jmcore/requirements.txt
RUN pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN pip install --no-cache-dir --user "/build/jmcore"

# Install directory_server dependencies
COPY directory_server/requirements.txt /build/directory_server/requirements.txt
RUN pip install --no-cache-dir --user -r /build/directory_server/requirements.txt

# Copy directory_server source and install
COPY directory_server/src /build/directory_server/src
COPY directory_server/pyproject.toml /build/directory_server/
RUN pip install --no-cache-dir --user /build/directory_server

# =============================================================================
# Production stage: Minimal runtime image
# =============================================================================
FROM python:${PYTHON_VERSION}-slim AS production

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

EXPOSE 5222 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]

CMD ["jm-directory-server"]

# =============================================================================
# Debug stage: Full Python image with debug symbols and tools
# =============================================================================
FROM python:${PYTHON_VERSION} AS debug-builder

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
COPY jmcore/requirements.txt /build/jmcore/requirements.txt
RUN pip install --no-cache-dir --user -r /build/jmcore/requirements.txt

# Copy jmcore source and install (with notifications support)
COPY jmcore/src /build/jmcore/src
COPY jmcore/pyproject.toml /build/jmcore/
RUN pip install --no-cache-dir --user "/build/jmcore"

# Install directory_server dependencies
COPY directory_server/requirements.txt /build/directory_server/requirements.txt
RUN pip install --no-cache-dir --user -r /build/directory_server/requirements.txt

# Copy directory_server source and install
COPY directory_server/src /build/directory_server/src
COPY directory_server/pyproject.toml /build/directory_server/
RUN pip install --no-cache-dir --user /build/directory_server

FROM python:${PYTHON_VERSION} AS debug

# Reproducible builds: Use SOURCE_DATE_EPOCH for consistent timestamps
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /app

# Install runtime and debug dependencies (sorted alphabetically for reproducibility)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    libsodium23 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user first
RUN useradd -m -u 1000 jm

# Copy Python packages from debug builder and set ownership
COPY --from=debug-builder --chown=jm:jm /root/.local /home/jm/.local

# Switch to non-root user
USER jm

# Make sure scripts are in PATH
ENV PATH=/home/jm/.local/bin:$PATH

EXPOSE 5222 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]

CMD ["jm-directory-server"]
