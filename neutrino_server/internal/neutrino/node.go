/*
Package neutrino provides a wrapper around the lightninglabs/neutrino library.

This package initializes and manages a neutrino light client node that uses
BIP157/BIP158 compact block filters for privacy-preserving blockchain access.
*/
package neutrino

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/neutrino"
)

// Config holds configuration for the neutrino node.
type Config struct {
	Network         string
	DataDir         string
	TorProxy        string
	ConnectPeers    string
	MaxPeers        int
	BanDuration     time.Duration
	FilterCacheSize int
	Logger          *btclog.Backend
}

// Node wraps a neutrino ChainService with additional functionality.
type Node struct {
	config       *Config
	chainParams  *chaincfg.Params
	chainService *neutrino.ChainService
	rescanMgr    *RescanManager
	logger       btclog.Logger

	mu           sync.RWMutex
	synced       bool
	blockHeight  int32
	filterHeight int32
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	TxID         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	Value        int64  `json:"value"`
	Address      string `json:"address"`
	ScriptPubKey string `json:"scriptpubkey"`
	Height       int32  `json:"height"`
}

// Transaction represents a blockchain transaction.
type Transaction struct {
	TxID        string `json:"txid"`
	Hex         string `json:"hex"`
	BlockHeight int32  `json:"block_height,omitempty"`
	BlockTime   int64  `json:"block_time,omitempty"`
}

// Status represents the current node status.
type Status struct {
	Synced       bool  `json:"synced"`
	BlockHeight  int32 `json:"block_height"`
	FilterHeight int32 `json:"filter_height"`
	Peers        int   `json:"peers"`
}

// NewNode creates a new neutrino node.
func NewNode(config *Config) (*Node, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}

	chainParams, err := getChainParams(config.Network)
	if err != nil {
		return nil, fmt.Errorf("invalid network %s: %w", config.Network, err)
	}

	logger := config.Logger.Logger("NTRN")
	logger.SetLevel(btclog.LevelInfo)

	node := &Node{
		config:      config,
		chainParams: chainParams,
		logger:      logger,
	}

	return node, nil
}

// Start initializes and starts the neutrino node.
func (n *Node) Start() error {
	n.logger.Info("Starting neutrino node...")

	// Create neutrino config
	neutrinoConfig := neutrino.Config{
		DataDir:         n.config.DataDir,
		ChainParams:     *n.chainParams,
		FilterCacheSize: uint64(n.config.FilterCacheSize),
	}

	// Add peers if specified
	if n.config.ConnectPeers != "" {
		peers := strings.Split(n.config.ConnectPeers, ",")
		for _, peer := range peers {
			peer = strings.TrimSpace(peer)
			if peer != "" {
				neutrinoConfig.ConnectPeers = append(neutrinoConfig.ConnectPeers, peer)
			}
		}
	}

	// Add DNS seeds if no connect peers specified
	if len(neutrinoConfig.ConnectPeers) == 0 {
		neutrinoConfig.AddPeers = getDNSSeeds(n.config.Network)
	}

	// Create chain service
	chainService, err := neutrino.NewChainService(neutrinoConfig)
	if err != nil {
		return fmt.Errorf("failed to create chain service: %w", err)
	}

	n.chainService = chainService

	// Start the chain service
	if err := n.chainService.Start(); err != nil {
		return fmt.Errorf("failed to start chain service: %w", err)
	}

	// Create rescan manager
	n.rescanMgr = NewRescanManager(n.chainService)

	// Start sync monitoring goroutine
	go n.monitorSync()

	n.logger.Info("Neutrino node started")
	return nil
}

// Stop gracefully stops the neutrino node.
func (n *Node) Stop() error {
	n.logger.Info("Stopping neutrino node...")

	if n.chainService != nil {
		if err := n.chainService.Stop(); err != nil {
			return fmt.Errorf("failed to stop chain service: %w", err)
		}
	}

	n.logger.Info("Neutrino node stopped")
	return nil
}

// GetStatus returns the current node status.
func (n *Node) GetStatus() Status {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := 0
	if n.chainService != nil {
		peers = len(n.chainService.Peers())
	}

	return Status{
		Synced:       n.synced,
		BlockHeight:  n.blockHeight,
		FilterHeight: n.filterHeight,
		Peers:        peers,
	}
}

// GetBlockHeight returns the current block height.
func (n *Node) GetBlockHeight() int32 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.blockHeight
}

// GetBlockHeader returns the block header at the given height.
func (n *Node) GetBlockHeader(height int32) (*wire.BlockHeader, error) {
	if n.chainService == nil {
		return nil, errors.New("chain service not initialized")
	}

	blockHash, err := n.chainService.GetBlockHash(int64(height))
	if err != nil {
		return nil, fmt.Errorf("failed to get block hash: %w", err)
	}

	header, err := n.chainService.GetBlockHeader(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block header: %w", err)
	}

	return header, nil
}

// GetBlockHash returns the block hash at the given height.
func (n *Node) GetBlockHash(height int32) (*chainhash.Hash, error) {
	if n.chainService == nil {
		return nil, errors.New("chain service not initialized")
	}

	return n.chainService.GetBlockHash(int64(height))
}

// BroadcastTransaction broadcasts a transaction to the network.
func (n *Node) BroadcastTransaction(tx *wire.MsgTx) error {
	if n.chainService == nil {
		return errors.New("chain service not initialized")
	}

	// Use the pushtx package to broadcast
	return n.chainService.SendTransaction(tx)
}

// GetUTXOs scans for UTXOs belonging to the given addresses.
func (n *Node) GetUTXOs(addresses []string) ([]UTXO, error) {
	if n.rescanMgr == nil {
		return nil, errors.New("rescan manager not initialized")
	}

	return n.rescanMgr.GetUTXOs(addresses)
}

// WatchAddress adds an address to the watch list.
func (n *Node) WatchAddress(address string) error {
	if n.rescanMgr == nil {
		return errors.New("rescan manager not initialized")
	}

	return n.rescanMgr.WatchAddress(address)
}

// Rescan triggers a rescan from the given height.
func (n *Node) Rescan(startHeight int32, addresses []string) error {
	if n.rescanMgr == nil {
		return errors.New("rescan manager not initialized")
	}

	return n.rescanMgr.Rescan(startHeight, addresses)
}

// monitorSync monitors the sync status and updates internal state.
func (n *Node) monitorSync() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if n.chainService == nil {
			continue
		}

		// Get best block
		bestBlock, err := n.chainService.BestBlock()
		if err != nil {
			n.logger.Warnf("Failed to get best block: %v", err)
			continue
		}

		// Use IsCurrent() as the primary sync indicator
		// The neutrino library tracks filter sync internally
		isCurrent := n.chainService.IsCurrent()

		n.mu.Lock()
		n.blockHeight = bestBlock.Height
		n.filterHeight = bestBlock.Height // Assume filters are synced when blocks are synced
		n.synced = isCurrent
		n.mu.Unlock()

		if !n.synced {
			n.logger.Debugf("Syncing... blocks: %d", n.blockHeight)
		}
	}
}

// getChainParams returns the chain parameters for the given network.
func getChainParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet":
		return &chaincfg.TestNet3Params, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network: %s", network)
	}
}

// getDNSSeeds returns DNS seeds for the given network.
func getDNSSeeds(network string) []string {
	switch network {
	case "mainnet":
		return []string{
			"seed.bitcoin.sipa.be",
			"dnsseed.bluematt.me",
			"dnsseed.bitcoin.dashjr.org",
			"seed.bitcoinstats.com",
			"seed.bitcoin.jonasschnelli.ch",
		}
	case "testnet":
		return []string{
			"testnet-seed.bitcoin.jonasschnelli.ch",
			"seed.tbtc.petertodd.net",
			"testnet-seed.bluematt.me",
		}
	case "signet":
		return []string{
			"seed.signet.bitcoin.sprovoost.nl",
		}
	default:
		return []string{}
	}
}
