// Package monitor scans active network connections against the guard store.
// It logs or kills untrusted connections based on the selected mode.
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
	// ModeWatch logs suspicious connections without killing them.
	ModeWatch = "watch"
	// ModeEnforce kills suspicious connections and records the action.
	ModeEnforce = "enforce"
)

func normalizeMode(mode string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case ModeEnforce:
		return ModeEnforce
	default:
		return ModeWatch
	}
}

func remoteIP(address string) (net.IP, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, fmt.Errorf("empty remote address")
	}

	if host, _, err := net.SplitHostPort(address); err == nil {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid host %q", host)
		}

		return ip, nil
	}

	address = strings.TrimPrefix(address, "[")
	address = strings.TrimSuffix(address, "]")

	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid address %q", address)
	}

	return ip, nil
}

func logScanConnection(debug bool, ip, program, status string) {
	if !debug {
		return
	}

	slog.Info("scan connection", "ip", ip, "program", program, "status", status)
}

// RunScan inspects established connections and applies the selected trust and kill policy.
func RunScan(ctx context.Context, guardStore *store.Store, deghostClient *deghost.Client, mode string, debug bool) {
	if guardStore == nil {
		slog.Error("scan aborted: nil guard store")
		return
	}
	if deghostClient == nil {
		slog.Error("scan aborted: nil deghost client")
		return
	}

	selectedMode := normalizeMode(mode)
	if selectedMode != mode {
		slog.Warn("invalid scan mode; defaulting to watch", "mode", mode, "fallback", selectedMode)
	}

	fmt.Printf("[%s] Scanning connections (%s mode)...\n", time.Now().Format("15:04:05"), selectedMode)

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
		ip, err := remoteIP(conn.RAddress)
		if err != nil {
			slog.Warn("invalid IP address", "address", conn.RAddress, "err", err)
			continue
		}

		ipStr := ip.String()

		// Trust allowlisted IPs immediately.
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
			// Keep long-running connections trusted after their Pi-hole refresh window expires.
			if err := guardStore.UpdateEstablished(ipStr); err != nil {
				slog.Error("failed to update established", "address", conn.RAddress, "err", err)
			}
			continue
		}

		cachedFraudCheck, err := guardStore.GetRecentFraudCheck(ipStr)
		if err != nil {
			slog.Error("fraud cache lookup failed", "ip", ipStr, "program", conn.Program, "err", err)
			continue
		}

		if cachedFraudCheck != nil {
			if !cachedFraudCheck.ShouldKill {
				slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program, "reason", "cached-fraud-check")
				logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
				continue
			}

			logScanConnection(debug, ipStr, conn.Program, "vulnerable")
			slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program, "reason", "cached-fraud-check")
			if selectedMode == ModeWatch {
				slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
				continue
			}

			if err := guardStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
				slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
			}
			if err := somo.KillConnection(conn.PID); err != nil {
				slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
			} else {
				slog.Info("killed connection", "address", conn.RAddress)
			}
			continue
		}

		report, err := deghostClient.CheckIP(ctx, ipStr)
		if err != nil {
			slog.Error("deghost check failed", "ip", ipStr, "program", conn.Program, "err", err)
			continue
		}

		if report == nil {
			if err := guardStore.UpsertFraudCheck(ipStr, false); err != nil {
				slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
			}
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program, "reason", "403/private-or-reserved")
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		shouldKill := deghost.ShouldKill(report)
		if err := guardStore.UpsertFraudCheck(ipStr, shouldKill); err != nil {
			slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
		}

		if !shouldKill {
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program)
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		logScanConnection(debug, ipStr, conn.Program, "vulnerable")

		slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		if selectedMode == ModeWatch {
			slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
			continue
		}

		if err := guardStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
			slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
		}
		if err := somo.KillConnection(conn.PID); err != nil {
			slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
		} else {
			slog.Info("killed connection", "address", conn.RAddress)
		}
	}
}
