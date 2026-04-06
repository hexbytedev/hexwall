// Package monitor checks active network connections against the guard store
// and kills any that are not trusted.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hexbytedev/pihole-guard/internal/allowlist"
	"github.com/hexbytedev/pihole-guard/internal/deghost"
	"github.com/hexbytedev/pihole-guard/internal/somo"
	"github.com/hexbytedev/pihole-guard/internal/store"
)

const (
	ModeWatch   = "watch"
	ModeEnforce = "enforce"
)

func logScanConnection(debug bool, ip, program, status string) {
	if !debug {
		return
	}

	slog.Info("scan connection", "ip", ip, "program", program, "status", status)
}

// RunScan inspects established connections and applies detection/kill logic
// based on the selected mode.
func RunScan(ctx context.Context, guardStore *store.Store, deghostClient *deghost.Client, mode string, debug bool) {
	fmt.Printf("[%s] Scanning connections (%s mode)...\n", time.Now().Format("15:04:05"), mode)

	connections, err := somo.GetEstablishedConnections()
	if err != nil {
		slog.Error("error fetching connections", "err", err)
		return
	}

	if len(connections) == 0 {
		slog.Info("scan returned zero connections")
		return
	}

	for _, conn := range connections {
		// Extract the remote IP, handling both IPv4 and IPv6 formats.
		addr := strings.Trim(conn.RAddress, "[]")
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		ip := net.ParseIP(host)
		if ip == nil {
			slog.Warn("invalid IP address", "address", conn.RAddress)
			continue
		}

		ipStr := ip.String()

		// Always trust allowlisted IPs (loopback, private ranges, etc.)
		if allowlist.Contains(ip) {
			logScanConnection(debug, ipStr, conn.Program, "allowed")
			continue
		}

		allowed, err := guardStore.IsAllowed(ipStr)
		if err != nil {
			slog.Error("store lookup failed", "address", conn.RAddress, "err", err)
			continue
		}

		if allowed {
			logScanConnection(debug, ipStr, conn.Program, "allowed")
			// Stamp last_established so long-running connections survive
			// the Pi-hole 1-hour window.
			if err := guardStore.UpdateEstablished(ipStr); err != nil {
				slog.Error("failed to update established", "address", conn.RAddress, "err", err)
			}
			continue
		}

		report, err := deghostClient.CheckIP(ctx, ipStr)
		if err != nil {
			slog.Error("deghost check failed", "ip", ipStr, "program", conn.Program, "err", err)
			continue
		}

		if report == nil {
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program, "reason", "403/private-or-reserved")
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		if !deghost.ShouldKill(report) {
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program)
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		logScanConnection(debug, ipStr, conn.Program, "vulnerable")

		slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		if mode == ModeWatch {
			slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
			continue
		}

		if err := guardStore.LogKill(ip.String(), conn.PID, conn.Program); err != nil {
			slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
		}
		if err := somo.KillConnection(conn.PID); err != nil {
			slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
		} else {
			slog.Info("killed connection", "address", conn.RAddress)
		}
	}
}
