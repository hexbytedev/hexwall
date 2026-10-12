// Package monitor scans active network connections against the hexwall store.
// It logs or kills untrusted connections based on the selected mode.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hexbytedev/hexwall/internal/allowlist"
	"github.com/hexbytedev/hexwall/internal/connlist"
	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/enforcer"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/store"
	"github.com/hexbytedev/hexwall/internal/zeek"
)

const (
	// ModeWatch logs suspicious connections without killing them.
	ModeWatch = "watch"
	// ModeEnforce kills suspicious connections and records the action.
	ModeEnforce = "enforce"
)

// Scanner holds the long-lived collaborators and configuration flags the
// decision ladder needs. Construct it with a struct literal — every field is
// a plain dependency or flag with nothing to validate, so there's no
// NewScanner constructor.
type Scanner struct {
	Checker          *pihole.Checker
	Store            *store.Store
	DeghostClient    *deghost.Client
	ZeekClient       *zeek.Client
	ConnectionLister func() ([]connlist.Connection, error)
	Mode             string
	DeghostIP        bool
	DeghostDomain    bool
	Debug            bool
}

// scanSummary tracks per-scan outcome counts for the summary line.
type scanSummary struct {
	connections int
	allowlisted int
	withSNI     int
	withoutSNI  int
	trusted     int
	blocked     int
	unknown     int
	errored     int
}

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

// HandleZeekEvent evaluates a Zeek DNS-bypass notice against Pi-hole policy and persists it.
//
// A notice whose SNI is policy-blocked is handled like rung 4: the connection is killed in
// enforce mode and reported in watch mode. hexwall can only close sockets on the machine
// it runs on, so the connection is first looked up in this machine's socket list; a notice
// about another device (Zeek watching a mirrored port, say) is recorded but not acted on.
func (s *Scanner) HandleZeekEvent(event zeek.Event) {
	if s.Checker == nil || s.Store == nil {
		return
	}
	if event.SNI == "" {
		return
	}

	selectedMode := normalizeMode(s.Mode)
	blocked, err := s.alertBlockedByPolicy(event)
	if err != nil {
		slog.Warn("zeek policy lookup failed", "sni", event.SNI, "err", err)
		return
	}

	confidence := "medium"
	actionTaken := "logged"
	var conn connlist.Connection
	found := false

	if blocked {
		confidence = "high"
		slog.Warn("zeek bypass alert", "src_ip", event.SrcIP, "dst_ip", event.DstIP, "dst_port", event.DstPort, "sni", event.SNI, "mode", selectedMode)

		conn, found = s.findLocalConnection(event)
		switch {
		case !found:
			actionTaken = "not_on_this_host"
			slog.Warn("zeek bypass alert: connection is not on this machine (another device, or already closed); hexwall can only kill its own machine's connections",
				"src_ip", event.SrcIP, "src_port", event.SrcPort, "dst_ip", event.DstIP, "sni", event.SNI)
		case selectedMode == ModeEnforce:
			actionTaken = "kill_attempted"
		}
	} else {
		slog.Info("zeek notice was not policy-blocked", "src_ip", event.SrcIP, "dst_ip", event.DstIP, "dst_port", event.DstPort, "sni", event.SNI)
	}

	// Persist before acting, so the alert is on record even if the kill goes wrong.
	if err := s.Store.LogZeekAlert(event.SrcIP, event.DstIP, event.DstPort, event.SNI, blocked, confidence, actionTaken); err != nil {
		slog.Error("failed to persist zeek alert", "src_ip", event.SrcIP, "sni", event.SNI, "err", err)
	}

	if found {
		if ip, err := remoteIP(conn.RAddress); err == nil {
			s.applyBlockedOutcome(ip.String(), conn)
		}
	}
}

// alertBlockedByPolicy applies the ladder's policy rungs to a Zeek alert, in Run's order:
// rung 1 (local network), rung 3 (Pi-hole allowlist, which overrides gravity, as it does
// in Pi-hole itself) and only then rung 4 (denylist, gravity, regex). An allowlist lookup
// error is returned rather than read as "not allowed", so it can never lead to a kill.
func (s *Scanner) alertBlockedByPolicy(event zeek.Event) (bool, error) {
	if ip := net.ParseIP(event.DstIP); ip != nil && allowlist.Contains(ip) {
		return false, nil
	}
	allowed, err := s.Checker.IsAllowedByPolicy(event.SNI)
	if err != nil {
		return false, fmt.Errorf("allowlist lookup: %w", err)
	}
	if allowed {
		return false, nil
	}
	return s.Checker.IsBlockedByPolicy(event.SNI)
}

// findLocalConnection looks a Zeek notice's connection up in this machine's socket list.
// Zeek names a connection from the client's side (orig port -> resp IP:port); for a
// connection this machine opened, that is its local port and remote address.
func (s *Scanner) findLocalConnection(event zeek.Event) (connlist.Connection, bool) {
	wantIP := net.ParseIP(event.DstIP)
	if s.ConnectionLister == nil || event.SrcPort == "" || wantIP == nil {
		return connlist.Connection{}, false
	}

	connections, err := s.ConnectionLister()
	if err != nil {
		slog.Warn("zeek bypass alert: could not list connections", "err", err)
		return connlist.Connection{}, false
	}

	for _, conn := range connections {
		if conn.LPort != event.SrcPort || conn.RPort != event.DstPort {
			continue
		}
		if ip, err := remoteIP(conn.RAddress); err == nil && ip.Equal(wantIP) {
			return conn, true
		}
	}
	return connlist.Connection{}, false
}

// Run inspects established connections and applies the decision ladder.
//
// The ladder is ordered from cheapest/most-authoritative to most-expensive/least-authoritative:
//  1. Static CIDR allowlist (loopback, RFC1918, cloud metadata)
//  2. Zeek SNI presence — if no SNI, fall back to IP-only evaluation (step 7)
//  3. Pi-hole explicit allowlist (user intent, highest authority)
//  4. Pi-hole explicit denylist / gravity (user intent)
//  5. Inferred trust from DNS history (hexwall's own cache)
//  6. Unknown domain → deghost escalation if enabled; no action if disabled
//  7. IP-only fallback → deghost escalation if enabled; no action if disabled
//
// Safety property: with deghost disabled, only rung 4 (Pi-hole blocklist match) can kill.
func (s *Scanner) Run(ctx context.Context) {
	if s.Store == nil {
		slog.Error("scan aborted: nil hexwall store")
		return
	}

	if s.ConnectionLister == nil {
		slog.Warn("connection lister unset; defaulting to somo")
		s.ConnectionLister = connlist.GetEstablishedConnections
	}

	selectedMode := normalizeMode(s.Mode)
	if selectedMode != s.Mode {
		slog.Warn("invalid scan mode; defaulting to watch", "mode", s.Mode, "fallback", selectedMode)
	}

	connections, err := s.ConnectionLister()
	if err != nil {
		slog.Error("error fetching connections", "err", err)
		return
	}

	if len(connections) == 0 {
		slog.Info("scan returned zero connections")
		return
	}

	var summary scanSummary
	summary.connections = len(connections)

	for _, conn := range connections {
		ip, err := remoteIP(conn.RAddress)
		if err != nil {
			slog.Warn("invalid IP address", "address", conn.RAddress, "err", err)
			summary.errored++
			continue
		}

		ipStr := ip.String()

		// Rung 1: static CIDR allowlist.
		if allowlist.Contains(ip) {
			summary.allowlisted++
			summary.trusted++
			continue
		}

		// Rung 2: did Zeek see an SNI for this connection?
		var sniDomain string
		sniFound := false
		if s.ZeekClient != nil {
			if domain, ok := s.ZeekClient.Lookup(conn.LPort, ipStr, conn.RPort); ok {
				sniDomain = domain
				sniFound = true
				summary.withSNI++
			} else {
				summary.withoutSNI++
			}
		} else {
			summary.withoutSNI++
		}

		if !sniFound {
			// Rung 7: IP-only fallback — no SNI means non-TLS, pre-existing connection, or ECH.
			action := s.evaluateIPOnly(ctx, ipStr, conn)
			applyOutcome(&summary, action)
			continue
		}

		domain := strings.ToLower(strings.TrimSpace(sniDomain))

		// Rung 3: Pi-hole explicit allowlist — user intent outranks everything inferred.
		allowed, err := s.Checker.IsAllowedByPolicy(domain)
		if err != nil {
			// Fail-open: if we cannot determine whether a domain is explicitly allowed,
			// we must not act on a block from rung 4.  Rung 4 is the only rung that can
			// kill a connection, and killing a legitimate connection on the basis of
			// incomplete policy data is worse than missing one block.
			slog.Warn("domain allowlist lookup failed, skipping blocklist check", "domain", domain, "err", err)
		} else if allowed {
			if logErr := s.Store.LogSNIObservation(ipStr, domain, conn.LPort, store.OutcomePolicyAllowed); logErr != nil {
				slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
			}
			summary.trusted++
			continue
		}

		// Rung 4: Pi-hole explicit denylist / gravity — only rung that can kill.
		if err == nil {
			if blocked, err := s.Checker.IsBlockedByPolicy(domain); err != nil {
				slog.Warn("domain denylist lookup failed", "domain", domain, "err", err)
			} else if blocked {
				if logErr := s.Store.LogSNIObservation(ipStr, domain, conn.LPort, store.OutcomePolicyBlocked); logErr != nil {
					slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
				}
				slog.Warn("policy-blocked domain", "domain", domain, "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
				s.applyBlockedOutcome(ipStr, conn)
				summary.blocked++
				continue
			}
		}

		// Rung 5: inferred trust from DNS history — scoped to this IP.
		known := false
		knownDomains, err := s.Store.DomainsForIP(ipStr)
		if err != nil {
			slog.Debug("sni domain check failed", "domain", domain, "ip", ipStr, "err", err)
		} else {
			for _, knownDomain := range knownDomains {
				if pihole.DomainMatches(domain, knownDomain) {
					known = true
					break
				}
			}
		}
		outcome := store.OutcomeUnknown
		if known {
			outcome = store.OutcomeIPDomainMatch
		}
		if logErr := s.Store.LogSNIObservation(ipStr, domain, conn.LPort, outcome); logErr != nil {
			slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
		}

		if known {
			summary.trusted++
			continue
		}

		// Rung 6: unknown domain — deghost escalation if enabled.
		if !s.DeghostDomain {
			if s.Debug {
				slog.Info("unknown domain, deghost disabled; no action", "domain", domain, "ip", ipStr, "program", conn.Program)
			}
			summary.unknown++
			continue
		}

		shouldBlock, reason := false, ""

		if cached, err := s.Store.GetRecentDomainCheck(domain); err != nil {
			slog.Error("domain cache lookup failed", "domain", domain, "err", err)
			summary.errored++
			continue
		} else if cached != nil {
			shouldBlock = cached.ShouldBlock
			reason = "cached-domain-check"
		}

		if !shouldBlock && reason == "" {
			report, err := s.DeghostClient.CheckDomain(ctx, domain)
			if err != nil {
				slog.Error("deghost domain check failed", "domain", domain, "program", conn.Program, "err", err)
				summary.errored++
				continue
			}

			shouldBlock = deghost.ShouldBlockDomain(report)
			reason = "live-domain-check"
			if err := s.Store.UpsertDomainCheck(domain, shouldBlock); err != nil {
				slog.Error("failed to cache domain check", "domain", domain, "program", conn.Program, "err", err)
			}
		}

		if !shouldBlock {
			if s.Debug {
				slog.Info("unknown but clean domain", "domain", domain, "ip", ipStr, "program", conn.Program, "reason", reason)
			}
			summary.unknown++
			continue
		}

		slog.Warn("deghost-blocked domain", "domain", domain, "address", conn.RAddress, "pid", conn.PID, "program", conn.Program, "reason", reason)
		s.applyBlockedOutcome(ipStr, conn)
		summary.blocked++
	}

	fmt.Printf("[%s] Scan complete: %d connections, %d trusted, %d blocked, %d unknown (allowlisted=%d sni=%d no-sni=%d errored=%d)\n",
		time.Now().Format("15:04:05"), summary.connections, summary.trusted, summary.blocked, summary.unknown, summary.allowlisted, summary.withSNI, summary.withoutSNI, summary.errored)
}

// evaluateIPOnly handles the IP-only fallback path (rung 7) when no SNI is available.
// It returns "trusted", "blocked", "unknown", or "error".
// Every exit path records an IP observation before returning.
func (s *Scanner) evaluateIPOnly(ctx context.Context, ipStr string, conn connlist.Connection) string {
	allowed, err := s.Store.IsAllowed(ipStr)
	if err != nil {
		slog.Error("store lookup failed", "address", conn.RAddress, "err", err)
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if allowed {
		if err := s.Store.UpdateEstablished(ipStr); err != nil {
			slog.Error("failed to update established", "address", conn.RAddress, "err", err)
		}
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPTrusted); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "trusted"
	}

	if !s.DeghostIP {
		if s.Debug {
			slog.Info("unknown IP, deghost disabled; no action", "ip", ipStr, "program", conn.Program)
		}
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	cachedFraudCheck, err := s.Store.GetRecentFraudCheck(ipStr)
	if err != nil {
		slog.Error("fraud cache lookup failed", "ip", ipStr, "program", conn.Program, "err", err)
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if cachedFraudCheck != nil {
		if !cachedFraudCheck.ShouldKill {
			if s.Debug {
				slog.Info("unknown but clean IP (cached)", "ip", ipStr, "program", conn.Program)
			}
			if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
				slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
			}
			return "unknown"
		}

		slog.Warn("deghost-blocked IP (cached)", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPBlocked); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		s.applyBlockedOutcome(ipStr, conn)
		return "blocked"
	}

	report, err := s.DeghostClient.CheckIP(ctx, ipStr)
	if err != nil {
		slog.Error("deghost check failed", "ip", ipStr, "program", conn.Program, "err", err)
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if report == nil {
		if err := s.Store.UpsertFraudCheck(ipStr, false); err != nil {
			slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
		}
		if s.Debug {
			slog.Info("unknown but clean IP (private/reserved)", "ip", ipStr, "program", conn.Program)
		}
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPReserved); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	shouldKill := deghost.ShouldKill(report)
	if err := s.Store.UpsertFraudCheck(ipStr, shouldKill); err != nil {
		slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
	}

	if !shouldKill {
		if s.Debug {
			slog.Info("unknown but clean IP", "ip", ipStr, "program", conn.Program)
		}
		if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	slog.Warn("deghost-blocked IP", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
	if logErr := s.Store.LogIPObservation(ipStr, conn.Program, store.OutcomeIPBlocked); logErr != nil {
		slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
	}
	s.applyBlockedOutcome(ipStr, conn)
	return "blocked"
}

// applyBlockedOutcome enforces the kill/watch policy for a blocked connection.
func (s *Scanner) applyBlockedOutcome(ipStr string, conn connlist.Connection) {
	selectedMode := normalizeMode(s.Mode)
	if selectedMode == ModeWatch {
		slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		return
	}

	if err := s.Store.LogKill(ipStr, conn.PID, conn.Program); err != nil {
		slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
	}

	pidInt, err := enforcer.ParsePID(conn.PID)
	if err != nil {
		slog.Warn("invalid PID, skipping kill", "pid", conn.PID, "address", conn.RAddress, "err", err)
		return
	}

	// Prefers a connection-level kill (ss -K) so any other connection the same
	// process holds is left untouched; falls back to killing the whole process
	// when that isn't possible. See enforcer.KillConnection.
	if err := enforcer.KillConnection(pidInt, conn.Program, conn.LPort, ipStr, conn.RPort); err != nil {
		slog.Warn("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
	} else {
		slog.Info("killed connection", "address", conn.RAddress)
	}
}

// applyOutcome increments the appropriate summary counter for a given outcome string.
func applyOutcome(summary *scanSummary, outcome string) {
	switch outcome {
	case "trusted":
		summary.trusted++
	case "blocked":
		summary.blocked++
	case "unknown":
		summary.unknown++
	case "error":
		summary.errored++
	}
}
