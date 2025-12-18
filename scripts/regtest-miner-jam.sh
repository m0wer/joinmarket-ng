#!/bin/sh
# Setup script for Bitcoin Core regtest (JAM node)
# Creates the legacy jm_wallet required by reference JoinMarket
# This node peers with the main bitcoin node, so it doesn't need to mine

set -e

RPC_HOST="${RPC_HOST:-bitcoin-jam}"
RPC_PORT="${RPC_PORT:-18445}"
RPC_USER="${RPC_USER:-test}"
RPC_PASSWORD="${RPC_PASSWORD:-test}"

CLI="bitcoin-cli -chain=regtest -rpcconnect=$RPC_HOST -rpcport=$RPC_PORT -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD"

echo "Waiting for Bitcoin Core (JAM) to be ready..."
until $CLI getblockchaininfo > /dev/null 2>&1; do
    sleep 2
done
echo "Bitcoin Core (JAM) is ready"

# Create jm_wallet as a LEGACY wallet for reference JoinMarket compatibility
# The reference implementation requires a non-descriptor (legacy) wallet
# For Bitcoin Core v28.x with -deprecatedrpc=create_bdb, use descriptors=false
echo "Creating legacy jm_wallet for JoinMarket..."
$CLI -named createwallet wallet_name="jm_wallet" descriptors=false 2>/dev/null || true
$CLI loadwallet "jm_wallet" 2>/dev/null || true

# Verify wallet was created correctly
wallet_info=$($CLI -rpcwallet=jm_wallet getwalletinfo 2>/dev/null)
if echo "$wallet_info" | grep -q '"descriptors": false'; then
    echo "Legacy jm_wallet created successfully (descriptors=false)"
else
    echo "WARNING: jm_wallet may not be a legacy wallet!"
    echo "$wallet_info"
fi

# Wait for blocks to sync from main node
echo "Waiting for blocks to sync from main node..."
while true; do
    blockcount=$($CLI getblockcount 2>/dev/null || echo "0")
    if [ "$blockcount" -ge 101 ]; then
        echo "Synced $blockcount blocks"
        break
    fi
    echo "Syncing... ($blockcount blocks)"
    sleep 5
done

echo "JAM node setup complete. Keeping container running..."
# Keep container alive (it doesn't need to mine, just maintain the wallet)
while true; do
    sleep 60
    # Periodic health check
    $CLI getblockcount > /dev/null 2>&1 || echo "Warning: connection to bitcoind lost"
done
