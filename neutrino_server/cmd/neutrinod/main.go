/*
Neutrino server main entry point.

This server wraps the lightninglabs/neutrino BIP157/BIP158 light client
with a REST API for use by JoinMarket maker/taker clients.
*/
package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/btcsuite/btclog"
	"github.com/gorilla/mux"

	"github.com/joinmarket-webui/jm-refactor/neutrino_server/internal/api"
	"github.com/joinmarket-webui/jm-refactor/neutrino_server/internal/neutrino"
)

var (
	network         = flag.String("network", "mainnet", "Bitcoin network (mainnet, testnet, regtest, signet)")
	dataDir         = flag.String("datadir", "/data/neutrino", "Data directory for headers and filters")
	listenAddr      = flag.String("listen", "0.0.0.0:8334", "REST API listen address")
	torProxy        = flag.String("proxy", "", "Tor SOCKS5 proxy address (e.g., 127.0.0.1:9050)")
	connectPeers    = flag.String("connect", "", "Comma-separated list of peers to connect to")
	logLevel        = flag.String("loglevel", "info", "Log level (trace, debug, info, warn, error)")
	maxPeers        = flag.Int("maxpeers", 8, "Maximum number of peers to connect to")
	banDuration     = flag.Duration("banduration", 24*time.Hour, "Duration to ban misbehaving peers")
	filterCacheSize = flag.Int("filtercache", 4096, "Size of filter cache (number of filters)")
)

func main() {
	flag.Parse()

	// Setup logging
	backend := btclog.NewBackend(os.Stdout)
	logger := backend.Logger("MAIN")
	level, _ := btclog.LevelFromString(*logLevel)
	logger.SetLevel(level)

	logger.Infof("Starting Neutrino server on %s for %s network", *listenAddr, *network)

	// Create data directory
	if err := os.MkdirAll(*dataDir, 0750); err != nil {
		logger.Errorf("Failed to create data directory: %v", err)
		os.Exit(1)
	}

	// Initialize neutrino node
	nodeConfig := &neutrino.Config{
		Network:         *network,
		DataDir:         *dataDir,
		TorProxy:        *torProxy,
		ConnectPeers:    *connectPeers,
		MaxPeers:        *maxPeers,
		BanDuration:     *banDuration,
		FilterCacheSize: *filterCacheSize,
		Logger:          backend,
	}

	node, err := neutrino.NewNode(nodeConfig)
	if err != nil {
		logger.Errorf("Failed to create neutrino node: %v", err)
		os.Exit(1)
	}

	// Start the node
	if err := node.Start(); err != nil {
		logger.Errorf("Failed to start neutrino node: %v", err)
		os.Exit(1)
	}

	// Setup REST API
	router := mux.NewRouter()
	apiHandler := api.NewHandler(node, logger)
	apiHandler.RegisterRoutes(router)

	// Create HTTP server
	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in goroutine
	go func() {
		logger.Infof("REST API listening on %s", *listenAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")

	// Graceful shutdown
	if err := server.Close(); err != nil {
		logger.Warnf("HTTP server shutdown error: %v", err)
	}

	if err := node.Stop(); err != nil {
		logger.Warnf("Neutrino node shutdown error: %v", err)
	}

	logger.Info("Shutdown complete")
}
