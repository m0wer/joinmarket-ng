#!/bin/sh
# Fund maker wallets for E2E testing
# This script generates addresses from known mnemonics and mines BTC to them

set -e

RPC_HOST="${RPC_HOST:-jm-bitcoin}"
RPC_PORT="${RPC_PORT:-18443}"
RPC_USER="${RPC_USER:-test}"
RPC_PASSWORD="${RPC_PASSWORD:-test}"
BLOCKS_TO_MINE="${BLOCKS_TO_MINE:-112}"

CLI="bitcoin-cli -chain=regtest -rpcconnect=$RPC_HOST -rpcport=$RPC_PORT -rpcuser=$RPC_USER -rpcpassword=$RPC_PASSWORD"

echo "Waiting for Bitcoin Core to be ready..."
until $CLI getblockchaininfo > /dev/null 2>&1; do
    sleep 2
done
echo "Bitcoin Core is ready"

# Known wallet addresses derived from the test mnemonics:
# These are the first receive addresses (m/84'/1'/0'/0/0) for each wallet
# BIP84 native segwit path uses coin type 1 for testnet/regtest
#
# Maker1: "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
#   Address: bcrt1q6x4xurtda3szpc54knp6qpuh0jxgcjajmnmy89
#
# Maker2: "minute faint grape plate stock mercy tent world space opera apple rocket"
#   Address: bcrt1qfuzpvnf2lgg8z54p3xcjp8xf8x5ydla63tgud2
#
# Taker: "burden notable love elephant orbit couch message galaxy elevator exile drop toilet"
#   Address: bcrt1q84l5vscg3pvjn6se8jp4ruymtyh393ed5v2d9e
#
# These addresses are derived using BIP84 (native segwit) path for regtest/testnet

# Get current block height
blockcount=$($CLI getblockcount 2>/dev/null || echo "0")
echo "Current block height: $blockcount"

# Maker1 address (derived from: avoid whisper mesh corn...)
MAKER1_ADDR="bcrt1q6x4xurtda3szpc54knp6qpuh0jxgcjajmnmy89"

# Maker2 address (derived from: minute faint grape...)
MAKER2_ADDR="bcrt1qfuzpvnf2lgg8z54p3xcjp8xf8x5ydla63tgud2"

# Taker address (derived from: burden notable love...)
TAKER_ADDR="bcrt1q84l5vscg3pvjn6se8jp4ruymtyh393ed5v2d9e"

echo "Funding maker and taker wallets..."
echo "  Maker1: $MAKER1_ADDR"
echo "  Maker2: $MAKER2_ADDR"
echo "  Taker:  $TAKER_ADDR"

# Mine blocks to each address to fund them
# Each block gives 50 BTC on regtest
$CLI generatetoaddress $BLOCKS_TO_MINE "$MAKER1_ADDR"
echo "Mined $BLOCKS_TO_MINE blocks to Maker1"

$CLI generatetoaddress $BLOCKS_TO_MINE "$MAKER2_ADDR"
echo "Mined $BLOCKS_TO_MINE blocks to Maker2"

$CLI generatetoaddress $BLOCKS_TO_MINE "$TAKER_ADDR"
echo "Mined $BLOCKS_TO_MINE blocks to Taker"

# Mine some extra blocks for coinbase maturity
# After this, all wallets should have spendable funds
$CLI generatetoaddress 10 "$MAKER1_ADDR"

echo "Wallet funding complete!"
echo "Each wallet should have ~5500 BTC from coinbase rewards"

# Show final blockchain state
finalcount=$($CLI getblockcount 2>/dev/null)
echo "Final block height: $finalcount"
