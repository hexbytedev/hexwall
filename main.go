package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
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

func main() {
	dbPath := flag.String("db", "", "path to pihole-FTL.db (auto-detected if not set)")
	guardDB := flag.String("guard-db", "./pihole-guard.db", "path to local guard database")
	mode := flag.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flag.Bool("debug", false, "enable verbose per-connection scan logging")
	flag.Parse()

	selectedMode := strings.ToLower(strings.TrimSpace(*mode))
	if selectedMode != monitor.ModeWatch && selectedMode != monitor.ModeEnforce {
		slog.Error("invalid --mode value", "mode", *mode, "allowed", []string{monitor.ModeWatch, monitor.ModeEnforce})
		return
	}

	// Cancel everything cleanly on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Check if somo is installed.
	if err := somo.CheckInstalled(); err != nil {
		slog.Error("somo is not installed", "err", err, "tip", "install somo from https://github.com/theopfr/somo")
		return
	}

	// 2. Resolve Pi-hole DB path.
	resolvedDBPath := *dbPath
	if resolvedDBPath == "" {
		detected, err := detector.FindDBPath()
		if err != nil {
			slog.Error("could not find pi-hole installation", "err", err)
			return
		}

		resolvedDBPath = detected
		slog.Info("pi-hole database auto-detected", "path", resolvedDBPath)
	}

	// 3. Open Pi-hole DB (read-only).
	checker, err := pihole.NewChecker(&pihole.Config{DBPath: resolvedDBPath})
	if err != nil {
		slog.Error("failed to open pi-hole database", "path", resolvedDBPath, "err", err)
		return
	}
	defer checker.Close()

	// 4. Open guard DB (read-write, created if not exists).
	guardStore, err := store.NewStore(*guardDB)
	if err != nil {
		slog.Error("failed to open guard database", "path", *guardDB, "err", err)
		return
	}
	defer guardStore.Close()

	slog.Info("guard database ready", "path", *guardDB)

	deghostClient := deghost.NewClient("https://fraudcheckapi.hexbyte.dev", 5*time.Second)

	// 5. Build cache, do initial refresh before starting the monitor so the
	//    first tick doesn't kill legitimate connections.
	cache := pihole.NewIPCache(checker, guardStore)
	cache.Refresh(ctx)

	// 6. Keep the cache fresh in the background (every 30s).
	go cache.RunRefresh(ctx, 30*time.Second)

	fmt.Println("Starting network monitor...")
	fmt.Printf("> Connections will be checked every 10s in %s mode.\n", selectedMode)
	if *debug {
		fmt.Println("> Debug logging is enabled for every scanned connection.")
	}

	// 7. Monitor connections every 10s.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		case <-ticker.C:
			monitor.RunScan(ctx, guardStore, deghostClient, selectedMode, *debug)
		}
	}
}
