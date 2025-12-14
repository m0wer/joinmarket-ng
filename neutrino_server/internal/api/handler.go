/*
Package api provides the REST API for the neutrino server.
*/
package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/gorilla/mux"

	"github.com/joinmarket-webui/jm-refactor/neutrino_server/internal/neutrino"
)

// Handler provides REST API endpoints for the neutrino node.
type Handler struct {
	node   *neutrino.Node
	logger btclog.Logger
}

// NewHandler creates a new API handler.
func NewHandler(node *neutrino.Node, logger btclog.Logger) *Handler {
	return &Handler{
		node:   node,
		logger: logger,
	}
}

// RegisterRoutes registers all API routes.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Status
	r.HandleFunc("/v1/status", h.handleGetStatus).Methods("GET")

	// Block queries
	r.HandleFunc("/v1/block/{height}/header", h.handleGetBlockHeader).Methods("GET")
	r.HandleFunc("/v1/block/{height}/filter_header", h.handleGetFilterHeader).Methods("GET")

	// Transaction operations
	r.HandleFunc("/v1/tx/{txid}", h.handleGetTransaction).Methods("GET")
	r.HandleFunc("/v1/tx/broadcast", h.handleBroadcastTransaction).Methods("POST")

	// UTXO operations
	r.HandleFunc("/v1/utxos", h.handleGetUTXOs).Methods("POST")

	// Watch operations
	r.HandleFunc("/v1/watch/address", h.handleWatchAddress).Methods("POST")
	r.HandleFunc("/v1/watch/outpoint", h.handleWatchOutpoint).Methods("POST")

	// Rescan
	r.HandleFunc("/v1/rescan", h.handleRescan).Methods("POST")

	// Fee estimation
	r.HandleFunc("/v1/fees/estimate", h.handleEstimateFee).Methods("GET")

	// Peers
	r.HandleFunc("/v1/peers", h.handleGetPeers).Methods("GET")
}

// Response helpers

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) errorResponse(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Status endpoint
func (h *Handler) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.node.GetStatus()
	h.jsonResponse(w, status)
}

// Block header endpoint
func (h *Handler) handleGetBlockHeader(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	heightStr := vars["height"]

	height, err := strconv.ParseInt(heightStr, 10, 32)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid height")
		return
	}

	header, err := h.node.GetBlockHeader(int32(height))
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	blockHash, _ := h.node.GetBlockHash(int32(height))

	h.jsonResponse(w, map[string]interface{}{
		"hash":        blockHash.String(),
		"height":      height,
		"timestamp":   header.Timestamp.Unix(),
		"version":     header.Version,
		"prev_block":  header.PrevBlock.String(),
		"merkle_root": header.MerkleRoot.String(),
		"bits":        header.Bits,
		"nonce":       header.Nonce,
	})
}

// Filter header endpoint
func (h *Handler) handleGetFilterHeader(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	heightStr := vars["height"]

	height, err := strconv.ParseInt(heightStr, 10, 32)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid height")
		return
	}

	// Filter headers would come from the filter header store
	// This is a placeholder - full implementation needed
	h.jsonResponse(w, map[string]interface{}{
		"height":        height,
		"filter_header": "",
	})
}

// Transaction endpoint
func (h *Handler) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	txid := vars["txid"]

	// Neutrino doesn't store full transactions by default
	// This would require fetching from a peer or having received it
	h.errorResponse(w, http.StatusNotImplemented, "transaction lookup requires full block download")
	_ = txid
}

// Broadcast transaction endpoint
func (h *Handler) handleBroadcastTransaction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TxHex string `json:"tx_hex"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid transaction hex")
		return
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "failed to deserialize transaction")
		return
	}

	if err := h.node.BroadcastTransaction(&tx); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	txid := tx.TxHash().String()
	h.logger.Infof("Broadcast transaction: %s", txid)

	h.jsonResponse(w, map[string]string{
		"txid": txid,
	})
}

// UTXOs endpoint
func (h *Handler) handleGetUTXOs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addresses []string `json:"addresses"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	utxos, err := h.node.GetUTXOs(req.Addresses)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"utxos": utxos,
	})
}

// Watch address endpoint
func (h *Handler) handleWatchAddress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.node.WatchAddress(req.Address); err != nil {
		h.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	h.jsonResponse(w, map[string]string{
		"status": "ok",
	})
}

// Watch outpoint endpoint
func (h *Handler) handleWatchOutpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TxID string `json:"txid"`
		Vout uint32 `json:"vout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Store outpoint for watching
	// Full implementation would track this and notify on spend
	h.jsonResponse(w, map[string]string{
		"status": "ok",
	})
}

// Rescan endpoint
func (h *Handler) handleRescan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StartHeight int32    `json:"start_height"`
		Addresses   []string `json:"addresses"`
		Outpoints   []struct {
			TxID string `json:"txid"`
			Vout uint32 `json:"vout"`
		} `json:"outpoints"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.node.Rescan(req.StartHeight, req.Addresses); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.jsonResponse(w, map[string]string{
		"status": "started",
	})
}

// Fee estimation endpoint
func (h *Handler) handleEstimateFee(w http.ResponseWriter, r *http.Request) {
	targetBlocks := 6 // default
	if tb := r.URL.Query().Get("target_blocks"); tb != "" {
		if parsed, err := strconv.Atoi(tb); err == nil {
			targetBlocks = parsed
		}
	}

	// Neutrino doesn't have mempool-based fee estimation
	// Return reasonable defaults based on target
	var feeRate int
	switch {
	case targetBlocks <= 1:
		feeRate = 20
	case targetBlocks <= 3:
		feeRate = 10
	case targetBlocks <= 6:
		feeRate = 5
	default:
		feeRate = 2
	}

	h.jsonResponse(w, map[string]interface{}{
		"fee_rate":      feeRate,
		"target_blocks": targetBlocks,
	})
}

// Peers endpoint
func (h *Handler) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	status := h.node.GetStatus()

	h.jsonResponse(w, map[string]interface{}{
		"peers": []interface{}{}, // Would list connected peers
		"count": status.Peers,
	})
}
