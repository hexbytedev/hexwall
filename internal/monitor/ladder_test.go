package monitor

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hexbytedev/hexwall/internal/connlist"
	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/store"
)

// These tests walk Run's decision ladder rung by rung for a connection Zeek saw an SNI
// for. Each rung leaves its verdict in sni_observations.outcome; a kill leaves a row in
// killed_connections (PID 1, so the guardrails refuse it and no real process is touched).

// fakeSNI is an SNISource with fixed answers, keyed like zeek.Client: "lport|ip|rport".
type fakeSNI map[string]string

func (f fakeSNI) Lookup(localPort, remoteIP, remotePort string) (string, bool) {
	sni, ok := f[localPort+"|"+remoteIP+"|"+remotePort]
	return sni, ok
}

const ladderIP = "203.0.113.50"

// ladderScan runs one enforce-mode scan of a single connection to ladderIP whose SNI is sni.
func ladderScan(t *testing.T, scanner *Scanner, sni string) {
	t.Helper()
	conn := connlist.Connection{LPort: "40000", RAddress: ladderIP + ":443", RPort: "443", PID: "1", Program: "curl"}
	scanner.Mode = ModeEnforce
	scanner.ConnectionLister = func() ([]connlist.Connection, error) { return []connlist.Connection{conn}, nil }
	scanner.ZeekClient = fakeSNI{"40000|" + ladderIP + "|443": sni}
	scanner.Run(context.Background())
}

func sniOutcome(t *testing.T, dbPath, domain string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var outcome string
	if err := db.QueryRow(`SELECT outcome FROM sni_observations WHERE ip = ? AND domain = ?`, ladderIP, domain).Scan(&outcome); err != nil {
		t.Fatalf("no sni_observations row for %s: %v", domain, err)
	}
	return outcome
}

func killRows(t *testing.T, dbPath string) int {
	t.Helper()
	return queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, ladderIP)
}

// Rung 3 outranks rung 4: an allowlisted domain is trusted even though gravity has it.
func TestRunAllowlistedSNIIsTrusted(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO gravity (domain) VALUES ('ads.example.com')`); err != nil {
			t.Fatal(err)
		}
		insertDomain(t, db, "ads.example.com", 0)
	})
	hexwallStore, dbPath := newTestStore(t)

	ladderScan(t, &Scanner{Checker: checker, Store: hexwallStore}, "ads.example.com")

	if got := sniOutcome(t, dbPath, "ads.example.com"); got != string(store.OutcomePolicyAllowed) {
		t.Fatalf("outcome = %q, want %q", got, store.OutcomePolicyAllowed)
	}
	if got := killRows(t, dbPath); got != 0 {
		t.Fatalf("kill rows = %d, want 0", got)
	}
}

// Rung 4, for each way Pi-hole can block a domain: exact denylist, gravity, regex.
func TestRunBlockedSNIIsKilled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sni   string
		setup func(t *testing.T, db *sql.DB)
	}{
		{"denylist", "evil.example.com", func(t *testing.T, db *sql.DB) { insertDomain(t, db, "evil.example.com", 1) }},
		{"gravity", "ads.example.com", func(t *testing.T, db *sql.DB) {
			if _, err := db.Exec(`INSERT INTO gravity (domain) VALUES ('ads.example.com')`); err != nil {
				t.Fatal(err)
			}
		}},
		{"regex", "track.example.com", func(t *testing.T, db *sql.DB) { insertDomain(t, db, `^track\.`, 3) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := newTestChecker(t, func(db *sql.DB) { tc.setup(t, db) })
			hexwallStore, dbPath := newTestStore(t)

			ladderScan(t, &Scanner{Checker: checker, Store: hexwallStore}, tc.sni)

			if got := sniOutcome(t, dbPath, tc.sni); got != string(store.OutcomePolicyBlocked) {
				t.Fatalf("outcome = %q, want %q", got, store.OutcomePolicyBlocked)
			}
			if got := killRows(t, dbPath); got != 1 {
				t.Fatalf("kill rows = %d, want 1", got)
			}
		})
	}
}

// Rung 5: a domain Pi-hole resolved to this very IP is trusted.
func TestRunSNIKnownForThisIPIsTrusted(t *testing.T) {
	checker := newTestChecker(t, nil)
	hexwallStore, dbPath := newTestStore(t)
	if err := hexwallStore.UpsertAllowedIPDomain(ladderIP, "cdn.example.com"); err != nil {
		t.Fatal(err)
	}

	ladderScan(t, &Scanner{Checker: checker, Store: hexwallStore}, "www.cdn.example.com")

	if got := sniOutcome(t, dbPath, "www.cdn.example.com"); got != string(store.OutcomeIPDomainMatch) {
		t.Fatalf("outcome = %q, want %q", got, store.OutcomeIPDomainMatch)
	}
	if got := killRows(t, dbPath); got != 0 {
		t.Fatalf("kill rows = %d, want 0", got)
	}
}

// Rung 6 with deghost off (the default): an unknown domain is recorded, never killed,
// and no data leaves the machine.
func TestRunUnknownSNIWithoutDeghostIsNotKilled(t *testing.T) {
	checker := newTestChecker(t, nil)
	hexwallStore, dbPath := newTestStore(t)
	client := deghost.NewClient(failIfCalled(t).URL, time.Second)

	ladderScan(t, &Scanner{Checker: checker, Store: hexwallStore, DeghostClient: client}, "new.example.com")

	if got := sniOutcome(t, dbPath, "new.example.com"); got != string(store.OutcomeUnknown) {
		t.Fatalf("outcome = %q, want %q", got, store.OutcomeUnknown)
	}
	if got := killRows(t, dbPath); got != 0 {
		t.Fatalf("kill rows = %d, want 0", got)
	}
}

// Rung 6 with deghost on: a blacklisted verdict kills, and is cached so the next scan
// doesn't ask the API again.
func TestRunUnknownSNIDeghostBlockedIsKilledAndCached(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"status":"allowed","blacklisted":true}`))
	}))
	t.Cleanup(srv.Close)

	checker := newTestChecker(t, nil)
	hexwallStore, dbPath := newTestStore(t)
	scanner := &Scanner{Checker: checker, Store: hexwallStore, DeghostClient: deghost.NewClient(srv.URL, time.Second), DeghostDomain: true}

	ladderScan(t, scanner, "bad.example.com")
	ladderScan(t, scanner, "bad.example.com")

	if got := killRows(t, dbPath); got != 2 {
		t.Fatalf("kill rows = %d, want 2 (one per scan)", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("deghost called %d times, want 1: the second scan must use the cached verdict", got)
	}
}

// Rung 2 → 7: no SNI for the connection means the IP-only path decides, and no SNI
// verdict is recorded.
func TestRunWithoutSNIUsesIPOnlyPath(t *testing.T) {
	checker := newTestChecker(t, nil)
	hexwallStore, dbPath := newTestStore(t)

	conn := connlist.Connection{LPort: "40000", RAddress: ladderIP + ":443", RPort: "443", PID: "1", Program: "curl"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeEnforce, ZeekClient: fakeSNI{},
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{conn}, nil },
	}
	scanner.Run(context.Background())

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM sni_observations`); got != 0 {
		t.Fatalf("sni_observations rows = %d, want 0", got)
	}
	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM ip_observations WHERE ip = ?`, ladderIP); got != 1 {
		t.Fatalf("ip_observations rows = %d, want 1: the IP-only path must have run", got)
	}
}
