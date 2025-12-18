#!/bin/sh
# Auto-miner for Bitcoin Core regtest
# Mines initial blocks to mature coinbase, then mines when mempool has transactions

set -e

RPC_HOST="${RPC_HOST:-bitcoin}"
RPC_PORT="${RPC_PORT:-18443}"
RPC_USER="${RPC_USER:-test}"
RPC_PASSWORD="${RPC_PASSWORD:-test}"
MINE_INTERVAL="${MINE_INTERVAL:-10}"

CLI="bitcoin-cli -chain=regtest -rpcconnect=$RPC_HOST -rpcport=$RPC_PORT -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD"
CLI_MINER="$CLI -rpcwallet=miner"

echo "Waiting for Bitcoin Core to be ready..."
until $CLI getblockchaininfo > /dev/null 2>&1; do
    sleep 2
done
echo "Bitcoin Core is ready"

# Create miner wallet (descriptor wallet for modern Bitcoin Core)
$CLI createwallet "miner" 2>/dev/null || true
$CLI loadwallet "miner" 2>/dev/null || true

while true; do
    blockcount=$($CLI getblockcount 2>/dev/null || echo "0")

    # Initial setup - mine to mature coinbase (101 blocks needed)
    if [ "$blockcount" -lt 101 ]; then
        echo "Initial setup: mining blocks to mature coinbase ($blockcount/101)"
        addr=$($CLI_MINER getnewaddress)
        $CLI generatetoaddress 10 "$addr"
        sleep 1
        continue
    fi

    # Mine mempool transactions
    mempool_count=$($CLI getmempoolinfo | grep -o '"size": [0-9]*' | grep -o '[0-9]*')
    # Default to 0 if extraction fails
    mempool_count=${mempool_count:-0}

    if [ "$mempool_count" -gt 0 ]; then
        echo "Mining block with $mempool_count mempool transactions"
        addr=$($CLI_MINER getnewaddress)
        $CLI generatetoaddress 1 "$addr"
    fi

    sleep "$MINE_INTERVAL"
done
