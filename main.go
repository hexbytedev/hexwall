// Package main wires together Pi-hole discovery, cache refreshes, and connection monitoring.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/detector"
	"github.com/hexbytedev/hexwall/internal/monitor"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/somo"
	"github.com/hexbytedev/hexwall/internal/store"
)

const (
	deghostBaseURL         = "https://deghostapi.hexbyte.dev"
	deghostTimeout         = 5 * time.Second
	trustedRefreshInterval = 30 * time.Second
	connectionScanInterval = 10 * time.Second
)

var version = "dev"
var platform = runtime.GOOS + "/" + runtime.GOARCH

func main() {
	os.Exit(run())
}

func run() int {
	dbPath := flag.String("db", "", "path to pihole-FTL.db (auto-detected if not set)")
	hexwallDB := flag.String("hexwall-db", "./hexwall.db", "path to local hexwall database")
	mode := flag.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flag.Bool("debug", false, "enable verbose per-connection scan logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s (%s)\n", version, platform)
		return 0
	}

	selectedMode := strings.ToLower(strings.TrimSpace(*mode))
	if selectedMode != monitor.ModeWatch && selectedMode != monitor.ModeEnforce {
		slog.Error("invalid --mode value", "mode", *mode, "allowed", []string{monitor.ModeWatch, monitor.ModeEnforce})
		return 1
	}

	resolvedDBPath := strings.TrimSpace(*dbPath)
	hexwallDBPath := strings.TrimSpace(*hexwallDB)
	if hexwallDBPath == "" {
		slog.Error("invalid --hexwall-db value", "path", *hexwallDB)
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
	defer func() {
		if err := checker.Close(); err != nil {
			slog.Error("failed to close pi-hole database", "err", err)
		}
	}()

	// 4. Open the local hexwall database, creating it if needed.
	hexwallStore, err := store.NewStore(hexwallDBPath)
	if err != nil {
		slog.Error("failed to open hexwall database", "path", hexwallDBPath, "err", err)
		return 1
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			slog.Error("failed to close hexwall database", "err", err)
		}
	}()

	slog.Info("hexwall database ready", "path", hexwallDBPath)

	deghostClient := deghost.NewClient(deghostBaseURL, deghostTimeout)

	// 5. Refresh trusted IPs before starting the monitor so the first tick does not kill legitimate connections.
	cache := pihole.NewIPCache(checker, hexwallStore)
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
			monitor.RunScan(ctx, hexwallStore, deghostClient, selectedMode, *debug)
		}
	}
}
