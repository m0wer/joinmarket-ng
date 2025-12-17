# =============================================================================
# Base stage: shared configuration and dependency installation
# =============================================================================
ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim AS base

WORKDIR /app

# Install system dependencies for building coincurve
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install jmcore dependencies first (cached layer)
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source and install as editable
COPY jmcore/src /app/jmcore/src
COPY jmcore/pyproject.toml /app/jmcore/
RUN pip install --no-cache-dir -e /app/jmcore

# Install directory_server dependencies from locked requirements
COPY directory_server/requirements.txt /app/directory_server/requirements.txt
RUN sed -i '/^-e ..\/jmcore/d' /app/directory_server/requirements.txt && \
    pip install --no-cache-dir -r /app/directory_server/requirements.txt

# Copy directory_server source and install as editable
COPY directory_server /app/directory_server
RUN pip install --no-cache-dir -e /app/directory_server

RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

EXPOSE 5222 8080

ENV NETWORK=mainnet
ENV HOST=0.0.0.0
ENV PORT=5222
ENV LOG_LEVEL=INFO
ENV HEALTH_CHECK_HOST=0.0.0.0
ENV HEALTH_CHECK_PORT=8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]

CMD ["jm-directory-server"]

# =============================================================================
# Production stage: slim image (default)
# =============================================================================
FROM base AS production

# No additional changes needed - base already uses slim image

# =============================================================================
# Debug stage: full Python image with debug symbols + debugging tools
# =============================================================================
FROM python:${PYTHON_VERSION} AS debug-base

RUN apt update && \
    apt install --no-install-recommends -y gdb && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install jmcore dependencies first (cached layer)
COPY jmcore/requirements.txt /app/jmcore/requirements.txt
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source and install as editable
COPY jmcore /app/jmcore
RUN pip install --no-cache-dir -e /app/jmcore

# Install directory_server dependencies from locked requirements
COPY directory_server/requirements.txt /app/directory_server/requirements.txt
RUN sed -i '/^-e ..\/jmcore/d' /app/directory_server/requirements.txt && \
    pip install --no-cache-dir -r /app/directory_server/requirements.txt

# Copy directory_server source and install as editable
COPY directory_server /app/directory_server
RUN pip install --no-cache-dir -e /app/directory_server

# Install debugging tools:
# - pdbpp: enhanced Python debugger with syntax highlighting and tab completion
# - memray: memory profiler for tracking allocations and finding memory leaks
RUN pip install --no-cache-dir pdbpp memray

RUN useradd -m -u 1000 jm && \
    chown -R jm:jm /app

USER jm

EXPOSE 5222 8080

ENV NETWORK=mainnet
ENV HOST=0.0.0.0
ENV PORT=5222
ENV LOG_LEVEL=DEBUG
ENV HEALTH_CHECK_HOST=0.0.0.0
ENV HEALTH_CHECK_PORT=8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]

CMD ["jm-directory-server"]

FROM debug-base AS debug
