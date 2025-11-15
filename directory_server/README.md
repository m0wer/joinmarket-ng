# JoinMarket Directory Server

Relay server for peer discovery and message routing in the JoinMarket network.

## Features

- **Peer Discovery**: Register and discover active peers
- **Message Routing**: Forward public broadcasts and private messages
- **Connection Management**: Handle peer connections and disconnections
- **Handshake Protocol**: Verify peer compatibility and network
- **High Performance**: Async I/O with optimized message handling
- **Observability**: Structured logging with loguru
- **Tor Hidden Service**: Run behind Tor for privacy (via separate container)

## Installation

```bash
# Install jmcore first
cd ../jmcore
pip install -e .

# Install directory server
cd ../directory_server
pip install -e .

# Development
pip install -e ".[dev]"
```

## Configuration

Create a `.env` file or set environment variables:

```bash
# Network
NETWORK=mainnet  # mainnet, testnet, signet, regtest
HOST=127.0.0.1
PORT=5222

# Server
MAX_PEERS=1000
MESSAGE_RATE_LIMIT=100
LOG_LEVEL=INFO
```

## Running

### Docker Compose (Recommended)

The recommended deployment uses Docker Compose with an isolated network where the directory server runs behind a Tor hidden service for privacy.

#### Initial Setup

**Important**: The Tor data directory must be created with proper permissions before starting Docker Compose. If not created manually, Docker will create it as root, causing permission errors.

```bash
# Create required directories with correct permissions
mkdir -p tor/data tor/run
sudo chown -R 1000:1000 tor/data tor/run

# Start both directory server and Tor
docker compose up -d --build

# View logs
docker compose logs -f

# Get your onion address (available after first tor startup)
cat tor/data/jm_directory/hostname

# Stop services
docker compose down
```

#### Vanity Onion Address (Optional)

To create a vanity onion address with a custom prefix:

```bash
# Generate vanity address (this can take a while depending on prefix length)
docker run --rm -it --network none -v $PWD:/keys \
  ghcr.io/cathugger/mkp224o:master -d /keys prefix

# Move generated keys to tor data directory
mv prefix* tor/data/jm_directory/
sudo chown -R 1000:1000 tor/data/jm_directory/

# Restart tor to use the new keys
docker compose restart tor
```

**Note**: Longer prefixes take exponentially longer to generate. A 5-character prefix may take hours, 6+ characters may take days.

#### Network Architecture & Security

The Docker Compose setup provides maximum security through network isolation:

- **directory_server**: Runs on isolated internal network (`tor_network`) with **no external internet access**
  - Cannot make outbound connections to the internet
  - Cannot be reached directly from the internet
  - Only accessible through the Tor hidden service
- **tor**: Acts as a secure gateway
  - Connected to both internal network (`tor_network`) and external network
  - Forwards hidden service traffic to directory_server on port 5222
  - Provides .onion address for privacy

This architecture ensures:
- The directory server cannot leak information or be exploited to make external connections
- All connections are anonymized through Tor
- Attack surface is minimized through network isolation
- Even if the directory server is compromised, it cannot access the internet directly

### Directory Structure

```
directory_server/
├── tor/
│   ├── conf/
│   │   └── torrc          # Tor configuration
│   ├── data/              # Hidden service keys (generated on first run)
│   │   └── jm_directory/
│   │       └── hostname   # Your .onion address
│   └── run/               # Tor runtime files
└── logs/                  # Directory server logs
```

### Development (Local)

```bash
# Start the directory server directly
jm-directory-server

# With custom config
jm-directory-server --config custom.env

# Development mode with debug logging
LOG_LEVEL=DEBUG jm-directory-server
```

**Note**: When running locally, you need to set up Tor separately and configure it to forward traffic to your local directory server.

## Architecture

### Components

1. **DirectoryServer**: Main server orchestration
   - Accept incoming connections
   - Handle disconnections
   - Coordinate components

2. **PeerRegistry**: Maintains peer state
   - Register/unregister peers
   - Track peer metadata
   - Peer discovery

3. **MessageRouter**: Routes messages between peers
   - Public message broadcasting
   - Private message routing
   - Message validation

4. **HandshakeHandler**: Handles peer handshakes
   - Protocol version negotiation
   - Network compatibility check
   - Peer authentication

### Message Flow

```
Client -> [Tor Hidden Service] -> Directory Server -> [Tor] -> Client
                                        |
                                   PeerRegistry
                                   MessageRouter
                                   ConnectionPool
```

The directory server is Tor-agnostic and only handles TCP connections. Tor privacy and anonymization is provided by running the server behind a Tor hidden service in a separate, isolated container. The directory server itself does not implement SOCKS5 or Tor protocols - it simply accepts TCP connections that are forwarded by the Tor container.

## Development

```bash
# Run tests
pytest

# Run load tests
pytest tests/test_load.py -v -s

# With coverage
pytest --cov

# Lint
ruff check src tests

# Format
ruff format src tests

# Type check
mypy src
```

### Performance

Load tests verified performance across real-world scenarios (50-200 concurrent peers):

- **Throughput**: 439 msg/sec peak, 37-206 msg/sec sustained
- **Memory**: ~8 KB per peer (1.6 MB for 200 peers)
- **Scalability**: Linear scaling, no degradation under load
- **Stability**: No memory leaks or failures

Run load tests: `pytest tests/test_load.py -v`

## API

### Handshake

Client connects and sends:
```json
{
  "type": 793,
  "line": "{\"app-name\":\"JoinMarket\",\"proto-ver\":9,...}"
}
```

Directory responds:
```json
{
  "type": 795,
  "line": "{\"app-name\":\"JoinMarket\",\"directory\":true,...}"
}
```

### Peerlist

Directory sends peer list:
```json
{
  "type": 789,
  "line": "nick1;onion1.onion:5222,nick2;onion2.onion:5222"
}
```

### Public Message

Client broadcasts:
```json
{
  "type": 687,
  "line": "nick!PUBLIC!absorder 12345 ..."
}
```

### Private Message

Client sends to peer:
```json
{
  "type": 685,
  "line": "alice!bob!fill 12345 ..."
}
```

## Performance

- Handles 1000+ concurrent connections
- Sub-10ms message routing latency
- Efficient memory usage with connection pooling
- Rate limiting to prevent abuse

## Security

- Tor hidden service for privacy (via separate container)
- Isolated network with no external access except through Tor
- Protocol version enforcement
- Network segregation (mainnet/testnet)
- Message validation and sanitization
- Rate limiting per peer
