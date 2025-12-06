# JoinMarket Orderbook Watcher

A clean, performant, and secure orderbook watcher for JoinMarket that aggregates offers from multiple directory nodes via Tor.

## Features

- 🔒 **Tor Integration**: Connects to directory nodes via Tor for privacy
- 📊 **Multi-Directory Aggregation**: Fetches and combines orderbooks from multiple directory nodes
- 🌐 **Web Interface**: Clean, modern UI with real-time updates
- 🔍 **Advanced Filtering**: Filter by offer type, directory node, and counterparty
- 📈 **Directory Statistics**: See offer counts per directory node
- 🔗 **Mempool.space Integration**: Validates fidelity bonds using mempool.space API
- 🐳 **Docker Support**: Easy deployment with Docker Compose

## Architecture

The orderbook watcher follows the clean architecture principles of this repository:

- **jmcore/models.py**: Core data models (Offer, FidelityBond, OrderBook)
- **jmcore/network.py**: Tor connection support
- **jmcore/mempool_api.py**: Mempool.space API client
- **orderbook_watcher/**: Application-specific code
  - **directory_client.py**: Connects to directory nodes
  - **aggregator.py**: Aggregates orderbooks from multiple nodes
  - **server.py**: HTTP server for API and static files

## Quick Start

### Using Docker Compose (Recommended)

1. Copy the environment file:
```bash
cd orderbook_watcher
cp .env.example .env
```

2. Edit `.env` and configure your directory nodes:
```bash
DIRECTORY_NODES=jmv2dirze66rwxsq7xv7frhmaufyicd3yz5if6obtavsskczjkndn6yd.onion:5222
```

3. Start the services:
```bash
docker-compose up -d
```

4. Access the web interface at http://localhost:8000

> **Note**: The `tor/conf/torrc` file must be manually created with the following content:
> ```
> SocksPort 0.0.0.0:9050
> ControlPort 0.0.0.0:9051
> CookieAuthentication 1
> DataDirectory /var/lib/tor
> Log notice stdout
> ```

### Manual Installation

1. Install dependencies:
```bash
cd jmcore
pip install -e .

cd ../orderbook_watcher
pip install -r requirements.txt
```

2. Make sure Tor is running on port 9050

3. Set environment variables:
```bash
export NETWORK=mainnet
export DIRECTORY_NODES=node1.onion:5222,node2.onion:5222
export TOR_SOCKS_HOST=127.0.0.1
export TOR_SOCKS_PORT=9050
export MEMPOOL_API_URL=https://mempool.sgn.space/api
export HTTP_HOST=0.0.0.0
export HTTP_PORT=8000
```

4. Run the watcher:
```bash
python -m orderbook_watcher.main
```

## Configuration

All configuration is done via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NETWORK` | Bitcoin network (mainnet/testnet/signet/regtest) | mainnet |
| `DIRECTORY_NODES` | Comma-separated list of directory nodes (host:port) | (required) |
| `TOR_SOCKS_HOST` | Tor SOCKS proxy host | 127.0.0.1 |
| `TOR_SOCKS_PORT` | Tor SOCKS proxy port | 9050 |
| `MEMPOOL_API_URL` | Mempool.space API base URL | http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion/api |
| `MEMPOOL_WEB_URL` | Base URL for transaction links (optional) | https://mempool.sgn.space |
| `MEMPOOL_WEB_ONION_URL` | Onion base URL for transaction links (optional) | http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion |
| `HTTP_HOST` | HTTP server bind address | 0.0.0.0 |
| `HTTP_PORT` | HTTP server port | 8000 |
| `UPDATE_INTERVAL` | Orderbook update interval in seconds | 60 |
| `LOG_LEVEL` | Logging level (DEBUG/INFO/WARNING/ERROR) | INFO |
| `MAX_MESSAGE_SIZE` | Maximum message size in bytes | 2097152 |
| `CONNECTION_TIMEOUT` | Connection timeout in seconds | 30.0 |

## Exposing as a Tor Hidden Service

You can expose the orderbook watcher as a Tor hidden service using the existing Tor container.

1. Update your `tor/conf/torrc` file:

```conf
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 1
DataDirectory /var/lib/tor
SafeLogging 0
Log notice stdout

# hidden service
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServiceVersion 3
HiddenServicePort 80 orderbook_watcher:8000
```

2. Restart the Tor container:
```bash
docker-compose restart tor
```

3. Get your onion address:
```bash
cat tor/data/hidden_service/hostname
```

4. (Optional) Configure onion-friendly links:
   If you want the web interface to use onion links for Mempool.space when visited via Tor, add this to your `.env`:
```bash
MEMPOOL_WEB_ONION_URL=http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion
```

## API Endpoints

### GET /
Web interface for viewing the orderbook

### GET /orderbook.json
Returns the aggregated orderbook in JSON format:

```json
{
  "timestamp": "2025-11-16T12:00:00.000000",
  "offers": [
    {
      "counterparty": "J5maker",
      "oid": 0,
      "ordertype": "sw0reloffer",
      "minsize": 100000,
      "maxsize": 10000000,
      "txfee": 1000,
      "cjfee": "0.0002",
      "fidelity_bond_value": 5000000,
      "directory_node": "node1.onion:5222"
    }
  ],
  "fidelitybonds": [...],
  "directory_nodes": ["node1.onion:5222", "node2.onion:5222"],
  "directory_stats": {
    "node1.onion:5222": {"offer_count": 10},
    "node2.onion:5222": {"offer_count": 8}
  }
}
```

### GET /health
Health check endpoint

## Web Interface Features

- **Real-time Updates**: Automatically refreshes every 60 seconds
- **Sorting**: Click column headers to sort by any field
- **Filtering**:
  - Filter by offer type (Native SegWit / SegWit)
  - Filter by directory node
  - Search by counterparty name
- **Statistics**:
  - Total offers count
  - Number of directory nodes
  - Fidelity bonds count
  - Offers per directory node breakdown
- **Dark Theme**: Easy on the eyes for long monitoring sessions

## Development

### Run Tests
```bash
cd orderbook_watcher
pytest
```

### Run with Coverage
```bash
pytest --cov=orderbook_watcher --cov-report=html
```

### Linting
```bash
ruff check src tests
```

### Formatting
```bash
ruff format src tests
```

### Type Checking
```bash
mypy src
```

## Security Considerations

- All connections to directory nodes go through Tor
- No private keys or sensitive data is stored
- Fidelity bonds are validated using public blockchain data
- Environment variables are used for configuration (no hardcoded secrets)
- Docker containers run with resource limits

## Comparison with Original Implementation

This implementation improves upon the original JoinMarket orderbook watcher:

### ✅ Improvements

- **Clean Architecture**: Reusable code in jmcore, specific logic in orderbook_watcher
- **Performance**: Async/await for concurrent directory node queries
- **Modern Stack**: Python 3.14+, Pydantic v2, aiohttp
- **Type Safety**: Full type hints and mypy strict mode
- **Docker Support**: Easy deployment with compose
- **No Bitcoin Core Required**: Uses mempool.space API instead
- **Directory Statistics**: Shows which directory has which offers
- **Filtering**: Filter by directory node, not available in original

### 🎯 Simplified

- No rotation buttons (auto-refresh only)
- No chart generation (focused on orderbook display)
- Clean, minimal UI without unnecessary features

## License

MIT
