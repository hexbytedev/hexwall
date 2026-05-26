// Package main wires together Pi-hole discovery, cache refreshes, and connection monitoring.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hexbytedev/pihole-guard/internal/deghost"
	"github.com/hexbytedev/pihole-guard/internal/detector"
	"github.com/hexbytedev/pihole-guard/internal/monitor"
	"github.com/hexbytedev/pihole-guard/internal/pihole"
	"github.com/hexbytedev/pihole-guard/internal/somo"
	"github.com/hexbytedev/pihole-guard/internal/store"
)

const (
	deghostBaseURL         = "https://fraudcheckapi.hexbyte.dev"
	deghostTimeout         = 5 * time.Second
	trustedRefreshInterval = 30 * time.Second
	connectionScanInterval = 10 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	dbPath := flag.String("db", "", "path to pihole-FTL.db (auto-detected if not set)")
	guardDB := flag.String("guard-db", "./pihole-guard.db", "path to local guard database")
	mode := flag.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flag.Bool("debug", false, "enable verbose per-connection scan logging")
	flag.Parse()

	selectedMode := strings.ToLower(strings.TrimSpace(*mode))
	if selectedMode != monitor.ModeWatch && selectedMode != monitor.ModeEnforce {
		slog.Error("invalid --mode value", "mode", *mode, "allowed", []string{monitor.ModeWatch, monitor.ModeEnforce})
		return 1
	}

	resolvedDBPath := strings.TrimSpace(*dbPath)
	guardDBPath := strings.TrimSpace(*guardDB)
	if guardDBPath == "" {
		slog.Error("invalid --guard-db value", "path", *guardDB)
		return 1
	}

	// Cancel background work cleanly on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Verify that somo is available before starting any monitoring.
	if err := somo.CheckInstalled(); err != nil {
		slog.Error("somo is not installed", "err", err, "tip", "install somo from https://github.com/theopfr/somo")
		return 1
	}

	// 2. Resolve the Pi-hole database path from --db or auto-detection.
	if resolvedDBPath == "" {
		detected, err := detector.FindDBPath()
		if err != nil {
			slog.Error("could not find pi-hole installation", "err", err)
			return 1
		}

		resolvedDBPath = detected
		slog.Info("pi-hole database auto-detected", "path", resolvedDBPath)
	}

	// 3. Open the Pi-hole database in read-only mode.
	checker, err := pihole.NewChecker(&pihole.Config{DBPath: resolvedDBPath})
	if err != nil {
		slog.Error("failed to open pi-hole database", "path", resolvedDBPath, "err", err)
		return 1
	}
	defer checker.Close()

	// 4. Open the local guard database, creating it if needed.
	guardStore, err := store.NewStore(guardDBPath)
	if err != nil {
		slog.Error("failed to open guard database", "path", guardDBPath, "err", err)
		return 1
	}
	defer guardStore.Close()

	slog.Info("guard database ready", "path", guardDBPath)

	deghostClient := deghost.NewClient(deghostBaseURL, deghostTimeout)

	// 5. Refresh trusted IPs before starting the monitor so the first tick does not kill legitimate connections.
	cache := pihole.NewIPCache(checker, guardStore)
	cache.Refresh(ctx)

	// 6. Keep the trusted-IP cache fresh in the background without re-running the startup refresh immediately.
	go func() {
		ticker := time.NewTicker(trustedRefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cache.Refresh(ctx)
			}
		}
	}()

	fmt.Println("Starting network monitor...")
	fmt.Printf("> Connections will be checked every %s in %s mode.\n", connectionScanInterval, selectedMode)
	if *debug {
		fmt.Println("> Debug logging is enabled for every scanned connection.")
	}

	// 7. Scan connections every 10 seconds.
	ticker := time.NewTicker(connectionScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return 0
		case <-ticker.C:
			monitor.RunScan(ctx, guardStore, deghostClient, selectedMode, *debug)
		}
	}
}
