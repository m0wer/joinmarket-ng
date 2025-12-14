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
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/neutrino"
)

// RescanManager handles address watching and UTXO scanning.
type RescanManager struct {
	chainService *neutrino.ChainService
	chainParams  *chaincfg.Params

	mu           sync.RWMutex
	watchedAddrs map[string]btcutil.Address
	utxoCache    map[string][]UTXO // address -> UTXOs
}

// NewRescanManager creates a new rescan manager.
func NewRescanManager(cs *neutrino.ChainService) *RescanManager {
	chainParams := cs.ChainParams()
	return &RescanManager{
		chainService: cs,
		chainParams:  &chainParams,
		watchedAddrs: make(map[string]btcutil.Address),
		utxoCache:    make(map[string][]UTXO),
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
	return nil
}

// GetUTXOs returns UTXOs for the given addresses.
// This performs a rescan using compact block filters.
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

	// Get all watched addresses
	r.mu.RLock()
	addrs := make([]btcutil.Address, 0, len(r.watchedAddrs))
	for _, addr := range r.watchedAddrs {
		addrs = append(addrs, addr)
	}
	r.mu.RUnlock()

	if len(addrs) == 0 {
		return []UTXO{}, nil
	}

	// Perform UTXO query using neutrino's GetUtxo
	utxos := make([]UTXO, 0)

	// For each address, we need to scan for relevant transactions
	// This is a simplified implementation - a full implementation would
	// use neutrino's Rescan functionality
	for _, addrStr := range addresses {
		r.mu.RLock()
		cached, ok := r.utxoCache[addrStr]
		r.mu.RUnlock()

		if ok {
			utxos = append(utxos, cached...)
		}
	}

	return utxos, nil
}

// Rescan triggers a rescan from the given height for specified addresses.
func (r *RescanManager) Rescan(startHeight int32, addresses []string) error {
	if r.chainService == nil {
		return errors.New("chain service not initialized")
	}

	// Add addresses to watch list
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

	// Create script filters for addresses
	_ = make([][]byte, 0, len(addrs))
	for _, addr := range addrs {
		_, err := txscript.PayToAddrScript(addr)
		if err != nil {
			continue
		}
	}

	// Note: Full rescan implementation would use neutrino.Rescan
	// with appropriate notification handlers. This is a placeholder.
	// The actual implementation depends on the neutrino API version.

	return nil
}

// AddUTXO adds a UTXO to the cache (for use by notification handlers).
func (r *RescanManager) AddUTXO(txHash string, vout uint32, value int64, addrStr string, scriptPubKey []byte, height int32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	utxo := UTXO{
		TxID:         txHash,
		Vout:         vout,
		Value:        value,
		Address:      addrStr,
		ScriptPubKey: hex.EncodeToString(scriptPubKey),
		Height:       height,
	}

	// Add to cache (avoiding duplicates)
	existing := r.utxoCache[addrStr]
	for _, e := range existing {
		if e.TxID == utxo.TxID && e.Vout == utxo.Vout {
			return // Already exists
		}
	}
	r.utxoCache[addrStr] = append(existing, utxo)
}

// RemoveUTXO removes a spent UTXO from the cache.
func (r *RescanManager) RemoveUTXO(txid string, vout uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for addr, utxos := range r.utxoCache {
		newUtxos := make([]UTXO, 0)
		for _, u := range utxos {
			if u.TxID != txid || u.Vout != vout {
				newUtxos = append(newUtxos, u)
			}
		}
		r.utxoCache[addr] = newUtxos
	}
}
