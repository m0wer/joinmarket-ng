/*
Package neutrino provides UTXO scanning using compact block filters.
*/
package neutrino

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/lightninglabs/neutrino"
)

// RescanManager handles address watching and UTXO scanning.
type RescanManager struct {
	chainService *neutrino.ChainService
	chainParams  *chaincfg.Params
	logger       btclog.Logger

	mu           sync.RWMutex
	watchedAddrs map[string]btcutil.Address
	utxoSet      map[string]UTXO // key: "txid:vout"
}

// NewRescanManager creates a new rescan manager.
func NewRescanManager(cs *neutrino.ChainService, logger btclog.Logger) *RescanManager {
	chainParams := cs.ChainParams()
	return &RescanManager{
		chainService: cs,
		chainParams:  &chainParams,
		logger:       logger,
		watchedAddrs: make(map[string]btcutil.Address),
		utxoSet:      make(map[string]UTXO),
	}
}

// WatchAddress adds an address to the watch list.
func (r *RescanManager) WatchAddress(addrStr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.watchedAddrs[addrStr]; exists {
		return nil // Already watching
	}

	addr, err := btcutil.DecodeAddress(addrStr, r.chainParams)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", addrStr, err)
	}

	r.watchedAddrs[addrStr] = addr
	r.logger.Debugf("Added watch address: %s", addrStr)
	return nil
}

// GetUTXOs returns UTXOs for the given addresses.
// This performs a rescan using compact block filters if needed.
func (r *RescanManager) GetUTXOs(addresses []string) ([]UTXO, error) {
	if r.chainService == nil {
		return nil, errors.New("chain service not initialized")
	}

	// Add addresses to watch list
	for _, addr := range addresses {
		if err := r.WatchAddress(addr); err != nil {
			return nil, err
		}
	}

	// Collect UTXOs for the requested addresses
	r.mu.RLock()
	defer r.mu.RUnlock()

	utxos := make([]UTXO, 0)
	addrSet := make(map[string]bool)
	for _, addr := range addresses {
		addrSet[addr] = true
	}

	for _, utxo := range r.utxoSet {
		if addrSet[utxo.Address] {
			utxos = append(utxos, utxo)
		}
	}

	r.logger.Debugf("GetUTXOs returning %d UTXOs for %d addresses", len(utxos), len(addresses))
	return utxos, nil
}

// Rescan triggers a rescan from the given height for specified addresses.
// This uses neutrino's block filter-based scanning.
func (r *RescanManager) Rescan(startHeight int32, addresses []string) error {
	if r.chainService == nil {
		return errors.New("chain service not initialized")
	}

	// Add addresses to watch list and collect btcutil.Address objects
	addrs := make([]btcutil.Address, 0, len(addresses))
	for _, addrStr := range addresses {
		if err := r.WatchAddress(addrStr); err != nil {
			return err
		}
		r.mu.RLock()
		addr := r.watchedAddrs[addrStr]
		r.mu.RUnlock()
		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		r.logger.Debug("Rescan called with no addresses")
		return nil
	}

	r.logger.Infof("Starting rescan from height %d for %d addresses", startHeight, len(addrs))

	// Get current best block
	bestBlock, err := r.chainService.BestBlock()
	if err != nil {
		return fmt.Errorf("failed to get best block: %w", err)
	}

	// Scan blocks from startHeight to bestBlock.Height
	return r.scanBlocks(startHeight, bestBlock.Height, addrs)
}

// scanBlocks scans blocks in the given range for transactions matching the addresses.
func (r *RescanManager) scanBlocks(startHeight, endHeight int32, addrs []btcutil.Address) error {
	r.logger.Infof("Scanning blocks %d to %d for %d addresses", startHeight, endHeight, len(addrs))

	// Build script filters for matching
	scripts := make([][]byte, 0, len(addrs))
	addrToScript := make(map[string]string) // scriptHex -> address
	for _, addr := range addrs {
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			r.logger.Warnf("Failed to create script for address %s: %v", addr.String(), err)
			continue
		}
		scripts = append(scripts, script)
		addrToScript[hex.EncodeToString(script)] = addr.String()
	}

	if len(scripts) == 0 {
		return errors.New("no valid scripts to scan for")
	}

	// Track spent outputs to remove from UTXO set
	spentOutputs := make(map[string]bool)
	foundUTXOs := make(map[string]UTXO)

	// Scan each block
	for height := startHeight; height <= endHeight; height++ {
		// Get block hash
		blockHash, err := r.chainService.GetBlockHash(int64(height))
		if err != nil {
			r.logger.Debugf("Failed to get block hash for height %d: %v", height, err)
			continue
		}

		// Get basic filter for this block
		filter, err := r.chainService.GetCFilter(*blockHash, wire.GCSFilterRegular)
		if err != nil {
			r.logger.Debugf("Failed to get filter for block %d: %v", height, err)
			continue
		}

		if filter == nil {
			continue
		}

		// Check if any of our scripts match the filter
		key := builder.DeriveKey(blockHash)
		matched, err := filter.MatchAny(key, scripts)
		if err != nil {
			r.logger.Debugf("Filter match error for block %d: %v", height, err)
			continue
		}

		if !matched {
			continue
		}

		r.logger.Debugf("Block %d filter matched, fetching full block", height)

		// Filter matched - fetch the full block to find exact transactions
		block, err := r.chainService.GetBlock(*blockHash)
		if err != nil {
			r.logger.Warnf("Failed to get block %d: %v", height, err)
			continue
		}

		// Scan all transactions in the block
		for _, tx := range block.Transactions() {
			txHash := tx.Hash().String()

			// Check inputs (mark UTXOs as spent)
			for _, txIn := range tx.MsgTx().TxIn {
				prevOut := txIn.PreviousOutPoint
				key := fmt.Sprintf("%s:%d", prevOut.Hash.String(), prevOut.Index)
				spentOutputs[key] = true
			}

			// Check outputs (find new UTXOs)
			for vout, txOut := range tx.MsgTx().TxOut {
				scriptHex := hex.EncodeToString(txOut.PkScript)
				if addrStr, ok := addrToScript[scriptHex]; ok {
					utxoKey := fmt.Sprintf("%s:%d", txHash, vout)
					utxo := UTXO{
						TxID:         txHash,
						Vout:         uint32(vout),
						Value:        txOut.Value,
						Address:      addrStr,
						ScriptPubKey: scriptHex,
						Height:       height,
					}
					foundUTXOs[utxoKey] = utxo
					r.logger.Infof("Found UTXO: %s:%d value=%d address=%s", txHash, vout, txOut.Value, addrStr)
				}
			}
		}
	}

	// Update UTXO set
	r.mu.Lock()
	defer r.mu.Unlock()

	// Add new UTXOs (if not spent)
	for utxoKey, utxo := range foundUTXOs {
		if !spentOutputs[utxoKey] {
			r.utxoSet[utxoKey] = utxo
		}
	}

	// Remove spent UTXOs
	for utxoKey := range spentOutputs {
		delete(r.utxoSet, utxoKey)
	}

	r.logger.Infof("Rescan complete: found %d UTXOs, %d spent", len(foundUTXOs), len(spentOutputs))
	return nil
}

// AddUTXO adds a UTXO to the cache (for use by notification handlers).
func (r *RescanManager) AddUTXO(txHash string, vout uint32, value int64, addrStr string, scriptPubKey []byte, height int32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	utxoKey := fmt.Sprintf("%s:%d", txHash, vout)
	utxo := UTXO{
		TxID:         txHash,
		Vout:         vout,
		Value:        value,
		Address:      addrStr,
		ScriptPubKey: hex.EncodeToString(scriptPubKey),
		Height:       height,
	}

	r.utxoSet[utxoKey] = utxo
	r.logger.Debugf("Added UTXO: %s", utxoKey)
}

// RemoveUTXO removes a spent UTXO from the cache.
func (r *RescanManager) RemoveUTXO(txid string, vout uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	utxoKey := fmt.Sprintf("%s:%d", txid, vout)
	delete(r.utxoSet, utxoKey)
	r.logger.Debugf("Removed UTXO: %s", utxoKey)
}
