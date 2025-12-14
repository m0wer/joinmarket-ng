# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go.mod and go.sum for dependency caching
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o neutrinod ./cmd/neutrinod

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 neutrino

# Create data directory
RUN mkdir -p /data/neutrino && chown neutrino:neutrino /data/neutrino

# Copy binary from builder
COPY --from=builder /build/neutrinod /usr/local/bin/

USER neutrino
WORKDIR /data

# Default configuration
ENV NETWORK=mainnet
ENV LISTEN_ADDR=0.0.0.0:8334
ENV DATA_DIR=/data/neutrino
ENV LOG_LEVEL=info
ENV MAX_PEERS=8

EXPOSE 8334

VOLUME ["/data/neutrino"]

ENTRYPOINT ["neutrinod"]
CMD ["--network=${NETWORK}", "--listen=${LISTEN_ADDR}", "--datadir=${DATA_DIR}", "--loglevel=${LOG_LEVEL}"]
