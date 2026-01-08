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

# Fidelity bond P2WSH address for Maker1
# Path: m/84'/1'/0'/2/0 with locktime 4099766400 (Dec 1, 2099)
# Generated with: python -m jmwallet generate-bond-address --mnemonic "avoid whisper..." --locktime 4099766400 --network regtest
MAKER1_FIDELITY_BOND_ADDR="bcrt1q7yv9xfz7vt5nn3nmpnrh899sxs5s9jnlqe94e8xx4jxc55xhtxcq0dgjy6"

echo "Funding maker and taker wallets..."
echo "  Maker1: $MAKER1_ADDR"
echo "  Maker1 Fidelity Bond: $MAKER1_FIDELITY_BOND_ADDR"
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

# Create a wallet in Bitcoin Core to fund the fidelity bond address
# We need to create a transaction from the mined funds
echo "Creating fidelity bond transaction..."

# Create a temporary descriptor wallet in Bitcoin Core for sending
# Parameters: wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
$CLI createwallet "fidelity_funder" false false "" false true true || true

# Get mining reward address to use as source
MINER_ADDR=$($CLI -rpcwallet=fidelity_funder getnewaddress "" "bech32")

# Mine blocks to the funder wallet - need 101+ to have spendable coinbase
# First block gives us 50 BTC, but need 100 confirmations to spend
echo "Mining blocks to funder wallet..."
$CLI generatetoaddress 1 "$MINER_ADDR"

# Mine 100 more blocks to mature the first coinbase (any address works)
$CLI generatetoaddress 100 "$MAKER1_ADDR"

# Verify we have spendable funds
BALANCE=$($CLI -rpcwallet=fidelity_funder getbalance)
echo "Funder wallet balance: $BALANCE BTC"

# Send 1 BTC to the fidelity bond address
echo "Sending 1 BTC to fidelity bond address..."
$CLI -rpcwallet=fidelity_funder sendtoaddress "$MAKER1_FIDELITY_BOND_ADDR" 1.0

# Mine a block to confirm the fidelity bond transaction
$CLI generatetoaddress 6 "$MAKER1_ADDR"

echo "Wallet funding complete!"
echo "Each wallet should have ~5500 BTC from coinbase rewards"
echo "Maker1 also has 1 BTC in fidelity bond (timelocked P2WSH)"

# Show final blockchain state
finalcount=$($CLI getblockcount 2>/dev/null)
echo "Final block height: $finalcount"
