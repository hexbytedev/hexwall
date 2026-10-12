// Package main wires together Pi-hole discovery, cache refreshes, and connection monitoring.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hexbytedev/hexwall/internal/connlist"
	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/detector"
	"github.com/hexbytedev/hexwall/internal/monitor"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/service"
	"github.com/hexbytedev/hexwall/internal/store"
	"github.com/hexbytedev/hexwall/internal/zeek"
)

const (
	deghostBaseURL         = "https://deghostapi.hexbyte.dev"
	deghostTimeout         = 5 * time.Second
	trustedRefreshInterval = 30 * time.Second
	connectionScanInterval = 10 * time.Second
)

var (
	version  = "dev"
	platform = runtime.GOOS + "/" + runtime.GOARCH
)

type runConfig struct {
	dbPath              string
	hexwallDBPath       string
	zeekLogPath         string
	zeekNoticeLog       string
	enableZeek          bool
	enableDeghostIP     bool
	enableDeghostDomain bool
	mode                string
	debug               bool
	showVersion         bool
}

func main() {
	os.Exit(run())
}

// parseFlags parses hexwall's run flags from args (os.Args[1:] in normal use).
func parseFlags(args []string) (*runConfig, error) {
	flags := flag.NewFlagSet("hexwall", flag.ContinueOnError)
	dbPath := flags.String("db", "", "path to pihole-FTL.db (auto-detected if not set)")
	hexwallDB := flags.String("hexwall-db", "./hexwall.db", "path to local hexwall database")
	zeekLogPath := flags.String("zeek-log", "", "path to zeek ssl.log for SNI-based domain verification (empty to skip)")
	zeekNoticeLog := flags.String("zeek-notice-log", "/opt/zeek/logs/current/notice.log", "path to Zeek notice.log for DNS-bypass alerts")
	enableZeek := flags.Bool("enable-zeek", false, "enable Zeek-based DNS-bypass detection")
	enableDeghostIP := flags.Bool("enable-deghost-ip", false, "send unrecognized IPs to the third-party reputation API (deghostapi.hexbyte.dev) on the IP-only fallback path")
	enableDeghostDomain := flags.Bool("enable-deghost-domain", false, "send unrecognized SNI domains to the third-party reputation API (deghostapi.hexbyte.dev) at rung 6")
	mode := flags.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flags.Bool("debug", false, "enable debug-level logging, including verbose per-connection scan logging")

	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}

	cfg := &runConfig{
		dbPath:              strings.TrimSpace(*dbPath),
		hexwallDBPath:       strings.TrimSpace(*hexwallDB),
		zeekLogPath:         strings.TrimSpace(*zeekLogPath),
		zeekNoticeLog:       strings.TrimSpace(*zeekNoticeLog),
		enableZeek:          *enableZeek,
		enableDeghostIP:     *enableDeghostIP,
		enableDeghostDomain: *enableDeghostDomain,
		mode:                strings.TrimSpace(*mode),
		debug:               *debug,
		showVersion:         *showVersion,
	}

	if cfg.showVersion {
		return cfg, nil
	}

	selectedMode := strings.ToLower(cfg.mode)
	if selectedMode != monitor.ModeWatch && selectedMode != monitor.ModeEnforce {
		return nil, fmt.Errorf("invalid --mode value %q: allowed %q or %q", cfg.mode, monitor.ModeWatch, monitor.ModeEnforce)
	}

	cfg.mode = selectedMode

	if cfg.hexwallDBPath == "" {
		return nil, fmt.Errorf("invalid --hexwall-db value %q", *hexwallDB)
	}

	return cfg, nil
}

func run() int {
	// `hexwall zeek-setup` installs the Zeek script whose notices hexwall reads, so the
	// script always matches this binary's parser.
	if len(os.Args) > 1 && os.Args[1] == "zeek-setup" {
		if err := zeek.Setup(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "zeek-setup:", err)
			return 1
		}

		return 0
	}

	if len(os.Args) > 1 && os.Args[1] == "install-service" {
		if err := installService(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "install-service:", err)
			return 1
		}

		return 0
	}

	if len(os.Args) > 1 && os.Args[1] == "uninstall" {
		if err := uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall:", err)
			return 1
		}

		return 0
	}

	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}

	if err != nil {
		slog.Error(err.Error())
		return 1
	}

	if cfg == nil {
		return 1
	}

	// Install the log handler first so every later slog call honours --debug.
	logLevel := slog.LevelInfo
	if cfg.debug {
		logLevel = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	if cfg.showVersion {
		fmt.Printf("%s (%s)\n", version, platform)
		return 0
	}

	// Windows is not supported at all, checked before any tool-availability probing.
	if runtime.GOOS == "windows" {
		slog.Error("windows is not supported by hexwall")
		return 1
	}

	slog.Info("detected OS", "os", runtime.GOOS)

	if fatal, msg := privilegeCheck(cfg.mode, os.Geteuid()); fatal {
		slog.Error(msg)
		return 1
	} else if msg != "" {
		slog.Warn(msg)
	}

	// Cancel background work cleanly on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Pick a connection-listing tool: ss (iproute2) if available, else somo.
	connectionLister, toolName, err := connlist.SelectBackend()
	if err != nil {
		fmt.Println("No connection-listing tool available:", err)
		slog.Error("no connection-listing tool available", "err", err)

		return 1
	}

	fmt.Printf("> Using %s for connection listing.\n", toolName)
	slog.Info("using connection-listing tool", "tool", toolName)

	// 2. Resolve the Pi-hole database path from --db or auto-detection.
	if cfg.dbPath == "" {
		detected, err := detector.FindDBPath()
		if err != nil {
			slog.Error("could not find pi-hole installation", "err", err)
			return 1
		}

		cfg.dbPath = detected
		slog.Info("pi-hole database auto-detected", "path", cfg.dbPath)
	}

	// 3. Open the Pi-hole database in read-only mode.
	checker, err := pihole.NewChecker(&pihole.Config{DBPath: cfg.dbPath})
	if err != nil {
		slog.Error("failed to open pi-hole database", "path", cfg.dbPath, "err", err)
		return 1
	}
	defer func() {
		if err := checker.Close(); err != nil {
			slog.Error("failed to close pi-hole database", "err", err)
		}
	}()

	// 3b. Log policy list summary from gravity.db.
	if counts, err := checker.PolicyCounts(); err != nil {
		slog.Warn("failed to read pi-hole policy counts", "err", err)
	} else if counts != nil {
		slog.Info("pihole policy lists loaded",
			"allow", counts["vw_allowlist"],
			"deny", counts["vw_denylist"],
			"gravity", counts["vw_gravity"],
			"regex_allow", counts["vw_regex_allowlist"],
			"regex_deny", counts["vw_regex_denylist"])

		if counts["vw_gravity"] == 0 {
			slog.Warn("pi-hole gravity list is empty; blocklist may be broken or not yet downloaded")
		}
	}

	if groups, err := checker.ExtraGroups(); err != nil {
		slog.Debug("could not count pi-hole groups", "err", err)
	} else if groups > 0 {
		slog.Warn("pi-hole uses groups; hexwall treats a block in any group as a block for this machine, which can be stricter than Pi-hole's own rules for it",
			"extra_groups", groups)
	}

	// 4. Open the local hexwall database, creating it if needed.
	hexwallStore, err := store.NewStore(cfg.hexwallDBPath)
	if err != nil {
		slog.Error("failed to open hexwall database", "path", cfg.hexwallDBPath, "err", err)

		if strings.Contains(err.Error(), "readonly database") || errors.Is(err, fs.ErrPermission) {
			slog.Error("the database file belongs to another user (often root, from an earlier sudo run): run with sudo, or pick another --hexwall-db")
		}

		return 1
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			slog.Error("failed to close hexwall database", "err", err)
		}
	}()

	slog.Info("hexwall database ready", "path", cfg.hexwallDBPath)

	// 4a. Prune stale rows from prior runs at startup.
	if result, err := hexwallStore.Prune(); err != nil {
		slog.Warn("initial prune failed", "err", err)
	} else if result != nil && (result.AllowedIPDomains+result.SNIObservations+result.IPObservations+result.KilledConnections+result.ZeekAlerts) > 0 {
		slog.Info("pruned stale rows",
			"allowed_ip_domains", result.AllowedIPDomains,
			"sni_observations", result.SNIObservations,
			"ip_observations", result.IPObservations,
			"killed_connections", result.KilledConnections,
			"zeek_alerts", result.ZeekAlerts)
	}

	// 4b. Start the Zeek ssl.log tailer when a path is provided.
	var zeekClient *zeek.Client

	if cfg.zeekLogPath != "" {
		zc, err := zeek.NewClient(&zeek.Config{
			LogPath: cfg.zeekLogPath,
		})
		if err != nil {
			slog.Error("failed to start zeek log watcher", "path", cfg.zeekLogPath, "err", err)
			return 1
		}

		defer zc.Close()

		zeekClient = zc
	}

	// deghost is opt-in: it sends every unrecognized domain to a third-party API,
	// which is a real privacy cost. Only construct the client when at least one check is enabled.
	var deghostClient *deghost.Client
	if cfg.enableDeghostIP || cfg.enableDeghostDomain {
		deghostClient = deghost.NewClient(deghostBaseURL, deghostTimeout)
	} else {
		slog.Info("deghost disabled; unrecognized connections will not be escalated to third-party API")
	}

	// Without an SNI source every connection takes the IP-only path, and with IP deghost off
	// that path never kills: enforce mode would silently protect nothing.
	if cfg.mode == monitor.ModeEnforce && cfg.zeekLogPath == "" && !cfg.enableDeghostIP {
		slog.Warn("enforce mode cannot kill any connection: no --zeek-log for Pi-hole rule matching and --enable-deghost-ip is off")
	}

	if cfg.mode == monitor.ModeEnforce && cfg.enableDeghostIP {
		slog.Warn("enforce mode with IP deghost enabled: an external reputation verdict can now terminate a local process; shared cloud provider ranges are known to produce false positives on such feeds")
	}

	scanner := &monitor.Scanner{
		Checker:          checker,
		Store:            hexwallStore,
		DeghostClient:    deghostClient,
		ZeekClient:       zeekClient,
		ConnectionLister: connectionLister,
		Mode:             cfg.mode,
		DeghostIP:        cfg.enableDeghostIP,
		DeghostDomain:    cfg.enableDeghostDomain,
		Debug:            cfg.debug,
	}

	var zeekEvents = make(chan zeek.Event, 100)

	if cfg.enableZeek && cfg.zeekNoticeLog != "" {
		go func() {
			if err := zeek.WatchNoticeLog(ctx, cfg.zeekNoticeLog, zeekEvents); err != nil {
				slog.Error("zeek notice watcher stopped", "path", cfg.zeekNoticeLog, "err", err)
			}
		}()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event := <-zeekEvents:
					scanner.HandleZeekEvent(event)
				}
			}
		}()
	}

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

				if err := checker.RefreshRegexLists(); err != nil {
					slog.Warn("pi-hole regex list refresh failed; keeping previous rules", "err", err)
				}
			}
		}
	}()

	// 6b. Periodically prune stale rows from the hexwall database.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if result, err := hexwallStore.Prune(); err != nil {
					slog.Warn("periodic prune failed", "err", err)
				} else if result != nil && (result.AllowedIPDomains+result.SNIObservations+result.IPObservations+result.KilledConnections+result.ZeekAlerts) > 0 {
					slog.Info("pruned stale rows",
						"allowed_ip_domains", result.AllowedIPDomains,
						"sni_observations", result.SNIObservations,
						"ip_observations", result.IPObservations,
						"killed_connections", result.KilledConnections,
						"zeek_alerts", result.ZeekAlerts)
				}
			}
		}
	}()

	fmt.Println("Starting network monitor...")
	fmt.Printf("> Connections will be checked every %s in %s mode.\n", connectionScanInterval, cfg.mode)

	if cfg.debug {
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
			scanner.Run(ctx)
		}
	}
}

// installService installs the systemd units that run hexwall with args at every boot.
func installService(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("only Linux with systemd is supported")
	}

	args = service.WithSafeMode(args)
	// Reject bad flags now: in a unit they would crash-loop at every boot instead.
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	binary, err := os.Executable()
	if err != nil {
		return err
	}

	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		return err
	}

	if strings.Contains(binary, "go-build") {
		return errors.New("this binary is temporary (go run); build hexwall and run the built binary instead")
	}

	opts := service.Options{Binary: binary, Args: args}
	if cfg.enableZeek || cfg.zeekLogPath != "" {
		if opts.Zeekctl, err = zeek.Zeekctl(); err != nil {
			return err
		}
	}

	if err := service.Install(os.Stdout, opts); err != nil {
		return err
	}

	if cfg.mode == monitor.ModeWatch {
		fmt.Println("\nRunning in watch mode: nothing is killed. Re-run with --mode enforce once the logs look right.")
	}

	return nil
}

// uninstall removes what install-service and zeek-setup added. The database (the kill and
// alert audit trail) and the binary are kept: hexwall didn't install the binary, and
// deleting evidence should be a separate, deliberate step.
func uninstall() error {
	if runtime.GOOS != "linux" {
		return errors.New("only Linux with systemd is supported")
	}
	// Services first, so Zeek stops before its script is removed.
	if err := service.Uninstall(os.Stdout); err != nil {
		return err
	}

	if err := zeek.Teardown(os.Stdout); err != nil {
		return err
	}

	fmt.Println(`
Kept on purpose:
  /var/lib/hexwall   the service's database, with its kill and alert history
                     (delete it with: sudo rm -r /var/lib/hexwall)
  this binary        delete it yourself if you installed it (e.g. /usr/local/bin/hexwall)`)

	return nil
}

// privilegeCheck says what running as euid means for mode. Without root, ss can't name
// other users' programs, ss -K can't close sockets (it needs CAP_NET_ADMIN), and other
// users' processes can't be signalled. Enforce mode would then report kills it can't
// make, so it refuses to start; watch mode still sees connections and only warns.
func privilegeCheck(mode string, euid int) (fatal bool, msg string) {
	if euid == 0 {
		return false, ""
	}

	if mode == monitor.ModeEnforce {
		return true, "enforce mode needs root: without it hexwall can't close connections or stop other users' programs (run with sudo)"
	}

	return false, "not running as root: other users' programs show without a name, and Zeek's logs may be unreadable (run with sudo for the full picture)"
}
