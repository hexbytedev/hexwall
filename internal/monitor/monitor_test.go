package monitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hexbytedev/hexwall/internal/connlist"
	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/store"
	"github.com/hexbytedev/hexwall/internal/zeek"

	_ "modernc.org/sqlite"
)

// ---- fixtures --------------------------------------------------------

// newTestStore creates a real *store.Store backed by a temp SQLite file and
// returns it along with its path, so tests can also open a second read-only
// connection to inspect tables the Store package doesn't expose a reader for
// (e.g. killed_connections, allowed_ips.last_established).
func newTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	s, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("store.NewStore() error = %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Store.Close() error = %v", err)
		}
	})

	return s, dbPath
}

// queryInt opens its own read-only connection to the sqlite file at dbPath and
// scans a single integer column. Used to inspect tables that *store.Store
// doesn't expose an exported reader for.
func queryInt(t *testing.T, dbPath, query string, args ...any) int {
	t.Helper()

	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: dbPath, RawQuery: "mode=ro"}).String())
	if err != nil {
		t.Fatalf("open %s for inspection: %v", dbPath, err)
	}
	defer func() {
		_ = db.Close()
	}()

	var got int
	if err := db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return got
}

// openTestGravityDB creates a temp gravity.db with the Pi-hole v6 views monitor's
// checker relies on. Mirrors internal/pihole/policy_test.go's helper of the same
// name, duplicated here because it is unexported in its own package.
func openTestGravityDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gravity.db")

	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: dbPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open test gravity db: %v", err)
	}

	schema := `
		CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, enabled INTEGER, date_added INTEGER, date_modified INTEGER, comment TEXT, groups TEXT);
		CREATE TABLE gravity (id INTEGER PRIMARY KEY, domain TEXT, adlist_id INTEGER);

		CREATE VIEW vw_allowlist AS SELECT domain FROM domainlist WHERE type = 0 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_denylist AS SELECT domain FROM domainlist WHERE type = 1 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_gravity AS SELECT domain FROM gravity;
		CREATE VIEW vw_regex_allowlist AS SELECT domain FROM domainlist WHERE type = 2 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_regex_denylist AS SELECT domain FROM domainlist WHERE type = 3 AND enabled = 1 AND TRIM(domain) <> '';
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create gravity schema: %v", err)
	}

	return db, dbPath
}

// insertDomain inserts a domain into domainlist. type 0 = allowlist, 1 = denylist.
func insertDomain(t *testing.T, db *sql.DB, domain string, listType int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO domainlist (type, domain, enabled) VALUES (?, ?, 1)`, listType, domain); err != nil {
		t.Fatalf("insert domain %q type %d: %v", domain, listType, err)
	}
}

// newTestChecker builds a real *pihole.Checker backed by temp SQLite files:
// an empty FTL query-history db and a gravity db seeded via gravitySetup.
func newTestChecker(t *testing.T, gravitySetup func(db *sql.DB)) *pihole.Checker {
	t.Helper()

	ftlPath := filepath.Join(t.TempDir(), "pihole-FTL.db")
	ftlDB, err := sql.Open("sqlite", "file:"+(&url.URL{Path: ftlPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("create ftl db: %v", err)
	}
	if _, err := ftlDB.Exec(`CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER, domain TEXT, status INTEGER, ip TEXT)`); err != nil {
		t.Fatalf("create ftl schema: %v", err)
	}
	if err := ftlDB.Close(); err != nil {
		t.Fatalf("close ftl db: %v", err)
	}

	gravDB, gravPath := openTestGravityDB(t)
	if gravitySetup != nil {
		gravitySetup(gravDB)
	}
	if err := gravDB.Close(); err != nil {
		t.Fatalf("close gravity db: %v", err)
	}

	checker, err := pihole.NewChecker(&pihole.Config{DBPath: ftlPath, GravityDBPath: gravPath})
	if err != nil {
		t.Fatalf("pihole.NewChecker() error = %v", err)
	}
	t.Cleanup(func() {
		if err := checker.Close(); err != nil {
			t.Errorf("Checker.Close() error = %v", err)
		}
	})

	return checker
}

// installFakeSomo writes an executable shell script named "somo" into a temp
// directory and prepends it to PATH, mirroring internal/connlist/connlist_test.go's helper.
func installFakeSomo(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "somo")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake somo: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// failIfCalled returns an httptest.Server that fails the test if it receives any request.
// Used to assert a code path never makes a live deghost call.
func failIfCalled(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call to deghost: %s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---- normalizeMode -----------------------------------------------------

func TestNormalizeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
		want string
	}{
		{"enforce lowercase", "enforce", ModeEnforce},
		{"enforce uppercase", "ENFORCE", ModeEnforce},
		{"enforce padded mixed case", " Enforce ", ModeEnforce},
		{"watch", "watch", ModeWatch},
		{"empty", "", ModeWatch},
		{"garbage", "banana", ModeWatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeMode(tt.mode); got != tt.want {
				t.Fatalf("normalizeMode(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

// ---- remoteIP ------------------------------------------------------------

func TestRemoteIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		wantIP  string
		wantErr bool
	}{
		{"ipv4 with port", "203.0.113.10:443", "203.0.113.10", false},
		{"bare ipv4", "203.0.113.10", "203.0.113.10", false},
		{"bracketed ipv6 with port", "[::1]:443", "::1", false},
		{"bare ipv6", "::1", "::1", false},
		{"invalid host with port", "not-an-ip:443", "", true},
		{"empty", "", "", true},
		{"malformed", "not-an-ip", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip, err := remoteIP(tt.address)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("remoteIP(%q) error = nil, want error", tt.address)
				}
				return
			}
			if err != nil {
				t.Fatalf("remoteIP(%q) error = %v, want nil", tt.address, err)
			}
			if ip.String() != tt.wantIP {
				t.Fatalf("remoteIP(%q) = %q, want %q", tt.address, ip.String(), tt.wantIP)
			}
		})
	}
}

// ---- applyOutcome --------------------------------------------------------

func TestApplyOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome string
		get     func(s scanSummary) int
	}{
		{"trusted", func(s scanSummary) int { return s.trusted }},
		{"blocked", func(s scanSummary) int { return s.blocked }},
		{"unknown", func(s scanSummary) int { return s.unknown }},
		{"error", func(s scanSummary) int { return s.errored }},
	}

	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			t.Parallel()
			var summary scanSummary
			applyOutcome(&summary, tt.outcome)
			if got := tt.get(summary); got != 1 {
				t.Fatalf("applyOutcome(%q) counter = %d, want 1", tt.outcome, got)
			}
		})
	}

	t.Run("unrecognized outcome increments nothing", func(t *testing.T) {
		t.Parallel()
		var want scanSummary
		got := want
		applyOutcome(&got, "garbage")
		if got != want {
			t.Fatalf("applyOutcome(garbage) summary = %+v, want unchanged %+v", got, want)
		}
	})
}

// ---- HandleZeekEvent ------------------------------------------------------

func TestHandleZeekEventBlockedDomainPersisted(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		insertDomain(t, db, "evil.example.com", 1) // denylist
	})
	hexwallStore, _ := newTestStore(t)

	event := zeek.Event{SrcIP: "10.0.0.5", DstIP: "203.0.113.20", DstPort: "443", SNI: "evil.example.com"}
	scanner := &Scanner{Checker: checker, Store: hexwallStore, Mode: ModeWatch}
	scanner.HandleZeekEvent(event)

	alert, err := hexwallStore.RecentZeekAlert(event.SrcIP, event.SNI)
	if err != nil {
		t.Fatalf("RecentZeekAlert() error = %v", err)
	}
	if alert == nil {
		t.Fatal("RecentZeekAlert() = nil, want persisted alert")
	}
	if !alert.Blocked {
		t.Fatal("alert.Blocked = false, want true for denylisted domain")
	}
}

func TestHandleZeekEventUnblockedDomainPersisted(t *testing.T) {
	checker := newTestChecker(t, nil)
	hexwallStore, _ := newTestStore(t)

	event := zeek.Event{SrcIP: "10.0.0.5", DstIP: "203.0.113.20", DstPort: "443", SNI: "clean.example.com"}
	scanner := &Scanner{Checker: checker, Store: hexwallStore, Mode: ModeWatch}
	scanner.HandleZeekEvent(event)

	alert, err := hexwallStore.RecentZeekAlert(event.SrcIP, event.SNI)
	if err != nil {
		t.Fatalf("RecentZeekAlert() error = %v", err)
	}
	if alert == nil {
		t.Fatal("RecentZeekAlert() = nil, want persisted alert")
	}
	if alert.Blocked {
		t.Fatal("alert.Blocked = true, want false for domain not on denylist")
	}
}

func TestHandleZeekEventNoopCases(t *testing.T) {
	t.Parallel()
	checker := newTestChecker(t, nil)
	hexwallStore, _ := newTestStore(t)

	// None of these should panic or write anything.
	(&Scanner{Store: hexwallStore, Mode: ModeWatch}).HandleZeekEvent(zeek.Event{SNI: "example.com"})
	(&Scanner{Checker: checker, Mode: ModeWatch}).HandleZeekEvent(zeek.Event{SNI: "example.com"})
	(&Scanner{Checker: checker, Store: hexwallStore, Mode: ModeWatch}).HandleZeekEvent(zeek.Event{SrcIP: "10.0.0.1", SNI: ""})
}

// A blocked DNS-bypass alert for a connection this machine owns is killed in enforce mode.
// The connection's PID is 1, which the enforcer's guardrails always refuse, so no real
// process is signalled; the audit row proves the kill path was taken.
func TestHandleZeekEventEnforceKillsLocalConnection(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		insertDomain(t, db, "evil.example.com", 1) // denylist
	})
	hexwallStore, dbPath := newTestStore(t)

	local := connlist.Connection{LPort: "55881", RAddress: "203.0.113.20:443", RPort: "443", PID: "1", Program: "curl"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeEnforce,
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{local}, nil },
	}
	event := zeek.Event{SrcIP: "192.168.0.223", SrcPort: "55881", DstIP: "203.0.113.20", DstPort: "443", SNI: "evil.example.com"}
	scanner.HandleZeekEvent(event)

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, "203.0.113.20"); got != 1 {
		t.Fatalf("killed_connections count = %d, want 1", got)
	}
	alert, err := hexwallStore.RecentZeekAlert(event.SrcIP, event.SNI)
	if err != nil || alert == nil {
		t.Fatalf("RecentZeekAlert() = %v, %v; want persisted alert", alert, err)
	}
	if alert.ActionTaken != "kill_attempted" {
		t.Fatalf("alert.ActionTaken = %q, want %q", alert.ActionTaken, "kill_attempted")
	}
}

// The allowlist exists to override gravity: allowlisting a domain a blocklist wrongly
// caught is its main use. Pi-hole answers such a domain, and the scan spares it at rung 3;
// a Zeek alert about it must not kill it either.
func TestHandleZeekEventAllowlistedDomainNotKilled(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO gravity (domain) VALUES ('cdn.example.com')`); err != nil {
			t.Fatal(err)
		}
		insertDomain(t, db, "cdn.example.com", 0) // allowlist
	})
	hexwallStore, dbPath := newTestStore(t)

	local := connlist.Connection{LPort: "55881", RAddress: "203.0.113.20:443", RPort: "443", PID: "1", Program: "firefox"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeEnforce,
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{local}, nil },
	}
	event := zeek.Event{SrcIP: "192.168.0.223", SrcPort: "55881", DstIP: "203.0.113.20", DstPort: "443", SNI: "cdn.example.com"}
	scanner.HandleZeekEvent(event)

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections`); got != 0 {
		t.Fatalf("killed_connections count = %d, want 0: the domain is allowlisted", got)
	}
	alert, err := hexwallStore.RecentZeekAlert(event.SrcIP, event.SNI)
	if err != nil || alert == nil {
		t.Fatalf("RecentZeekAlert() = %v, %v; want the alert recorded", alert, err)
	}
	if alert.Blocked {
		t.Fatal("alert recorded as blocked; Pi-hole allows this domain")
	}
}

// Rung 1 applies to Zeek alerts too: a connection to the local network is never killed.
func TestHandleZeekEventLocalNetworkNotKilled(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		insertDomain(t, db, "nas.example.com", 1) // denylist
	})
	hexwallStore, dbPath := newTestStore(t)

	local := connlist.Connection{LPort: "55881", RAddress: "192.168.0.10:443", RPort: "443", PID: "1", Program: "curl"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeEnforce,
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{local}, nil },
	}
	scanner.HandleZeekEvent(zeek.Event{SrcIP: "192.168.0.223", SrcPort: "55881", DstIP: "192.168.0.10", DstPort: "443", SNI: "nas.example.com"})

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections`); got != 0 {
		t.Fatalf("killed_connections count = %d, want 0: the destination is on the local network", got)
	}
}

// A connection that isn't in this machine's socket list belongs to another device (or has
// closed). hexwall cannot close a socket on another machine, so it records and warns.
func TestHandleZeekEventEnforceOtherDeviceNotKilled(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		insertDomain(t, db, "evil.example.com", 1)
	})
	hexwallStore, dbPath := newTestStore(t)

	unrelated := connlist.Connection{LPort: "40000", RAddress: "203.0.113.20:443", RPort: "443", PID: "1", Program: "curl"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeEnforce,
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{unrelated}, nil },
	}
	event := zeek.Event{SrcIP: "192.168.0.50", SrcPort: "55881", DstIP: "203.0.113.20", DstPort: "443", SNI: "evil.example.com"}
	scanner.HandleZeekEvent(event)

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections`); got != 0 {
		t.Fatalf("killed_connections count = %d, want 0", got)
	}
	alert, err := hexwallStore.RecentZeekAlert(event.SrcIP, event.SNI)
	if err != nil || alert == nil {
		t.Fatalf("RecentZeekAlert() = %v, %v; want persisted alert", alert, err)
	}
	if alert.ActionTaken != "not_on_this_host" {
		t.Fatalf("alert.ActionTaken = %q, want %q", alert.ActionTaken, "not_on_this_host")
	}
}

func TestHandleZeekEventWatchModeDoesNotKill(t *testing.T) {
	checker := newTestChecker(t, func(db *sql.DB) {
		insertDomain(t, db, "evil.example.com", 1)
	})
	hexwallStore, dbPath := newTestStore(t)

	local := connlist.Connection{LPort: "55881", RAddress: "203.0.113.20:443", RPort: "443", PID: "1", Program: "curl"}
	scanner := &Scanner{
		Checker: checker, Store: hexwallStore, Mode: ModeWatch,
		ConnectionLister: func() ([]connlist.Connection, error) { return []connlist.Connection{local}, nil },
	}
	scanner.HandleZeekEvent(zeek.Event{SrcIP: "192.168.0.223", SrcPort: "55881", DstIP: "203.0.113.20", DstPort: "443", SNI: "evil.example.com"})

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections`); got != 0 {
		t.Fatalf("killed_connections count = %d, want 0 in watch mode", got)
	}
}

// ---- applyBlockedOutcome ---------------------------------------------------

func TestApplyBlockedOutcomeWatchModeNeverLogsKill(t *testing.T) {
	hexwallStore, dbPath := newTestStore(t)

	conn := connlist.Connection{PID: "1", Program: "curl", RAddress: "203.0.113.10:443"}
	(&Scanner{Store: hexwallStore, Mode: ModeWatch}).applyBlockedOutcome("203.0.113.10", conn)

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections`); got != 0 {
		t.Fatalf("killed_connections count = %d, want 0 in watch mode", got)
	}
}

func TestApplyBlockedOutcomeEnforceModeLogsKillBeforeAttemptingIt(t *testing.T) {
	hexwallStore, dbPath := newTestStore(t)

	// PID 1 (init) is guaranteed to be refused by enforcer.KillProcess, but the
	// audit row must still be written first ("audit survives the kill").
	conn := connlist.Connection{PID: "1", Program: "curl", RAddress: "203.0.113.10:443"}
	(&Scanner{Store: hexwallStore, Mode: ModeEnforce}).applyBlockedOutcome("203.0.113.10", conn)

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, "203.0.113.10"); got != 1 {
		t.Fatalf("killed_connections count = %d, want 1 even though the kill itself was refused", got)
	}
}

func TestApplyBlockedOutcomeInvalidPIDLogsWarningAndReturns(t *testing.T) {
	hexwallStore, dbPath := newTestStore(t)

	conn := connlist.Connection{PID: "not-a-pid", Program: "curl", RAddress: "203.0.113.11:443"}
	(&Scanner{Store: hexwallStore, Mode: ModeEnforce}).applyBlockedOutcome("203.0.113.11", conn)

	// LogKill happens before ParsePID, so the audit row is still written.
	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, "203.0.113.11"); got != 1 {
		t.Fatalf("killed_connections count = %d, want 1 (audit before parse failure)", got)
	}
}

// ---- evaluateIPOnly --------------------------------------------------------

func TestEvaluateIPOnlyTrustedIPUpdatesEstablished(t *testing.T) {
	hexwallStore, dbPath := newTestStore(t)
	if err := hexwallStore.UpsertAllowedIP("203.0.113.20", "example.com"); err != nil {
		t.Fatalf("UpsertAllowedIP() error = %v", err)
	}

	srv := failIfCalled(t)
	client := deghost.NewClient(srv.URL, time.Second)

	conn := connlist.Connection{Program: "curl", RAddress: "203.0.113.20:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: true, Mode: ModeWatch}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.20", conn)
	if got != "trusted" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "trusted")
	}

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM allowed_ips WHERE ip = ? AND last_established IS NOT NULL`, "203.0.113.20"); got != 1 {
		t.Fatal("UpdateEstablished was not applied for a trusted IP")
	}
}

func TestEvaluateIPOnlyDeghostDisabledReturnsUnknown(t *testing.T) {
	hexwallStore, _ := newTestStore(t)
	srv := failIfCalled(t)
	client := deghost.NewClient(srv.URL, time.Second)

	conn := connlist.Connection{Program: "curl", RAddress: "203.0.113.21:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: false, Mode: ModeWatch}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.21", conn)
	if got != "unknown" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "unknown")
	}
}

func TestEvaluateIPOnlyCachedCleanReturnsUnknownNoHTTPCall(t *testing.T) {
	hexwallStore, _ := newTestStore(t)
	if err := hexwallStore.UpsertFraudCheck("203.0.113.22", false); err != nil {
		t.Fatalf("UpsertFraudCheck() error = %v", err)
	}

	srv := failIfCalled(t)
	client := deghost.NewClient(srv.URL, time.Second)

	conn := connlist.Connection{Program: "curl", RAddress: "203.0.113.22:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: true, Mode: ModeWatch}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.22", conn)
	if got != "unknown" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "unknown")
	}
}

func TestEvaluateIPOnlyCachedBlockedReturnsBlockedAndKills(t *testing.T) {
	hexwallStore, dbPath := newTestStore(t)
	if err := hexwallStore.UpsertFraudCheck("203.0.113.23", true); err != nil {
		t.Fatalf("UpsertFraudCheck() error = %v", err)
	}

	srv := failIfCalled(t)
	client := deghost.NewClient(srv.URL, time.Second)

	// PID 1 keeps the actual kill attempt safely refused by enforcer guardrails.
	conn := connlist.Connection{PID: "1", Program: "curl", RAddress: "203.0.113.23:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: true, Mode: ModeEnforce}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.23", conn)
	if got != "blocked" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "blocked")
	}

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, "203.0.113.23"); got != 1 {
		t.Fatal("applyBlockedOutcome was not invoked for a cached blocked verdict")
	}
}

func TestEvaluateIPOnlyLiveCheckPrivateReservedCachesClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	client := deghost.NewClient(srv.URL, time.Second)

	hexwallStore, _ := newTestStore(t)
	conn := connlist.Connection{Program: "curl", RAddress: "203.0.113.24:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: true, Mode: ModeWatch}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.24", conn)
	if got != "unknown" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "unknown")
	}

	entry, err := hexwallStore.GetRecentFraudCheck("203.0.113.24")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry == nil {
		t.Fatal("GetRecentFraudCheck() = nil, want a cached clean entry after private/reserved verdict")
	}
	if entry.ShouldKill {
		t.Fatal("GetRecentFraudCheck().ShouldKill = true, want false for private/reserved verdict")
	}
}

func TestEvaluateIPOnlyLiveCheckShouldKillCachesAndBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deghost.IPReport{
			IP:       "203.0.113.25",
			Security: deghost.SecurityReport{IsAbuser: true},
		})
	}))
	defer srv.Close()
	client := deghost.NewClient(srv.URL, time.Second)

	hexwallStore, dbPath := newTestStore(t)
	conn := connlist.Connection{PID: "1", Program: "curl", RAddress: "203.0.113.25:443"}
	scanner := &Scanner{Store: hexwallStore, DeghostClient: client, DeghostIP: true, Mode: ModeEnforce}
	got := scanner.evaluateIPOnly(context.Background(), "203.0.113.25", conn)
	if got != "blocked" {
		t.Fatalf("evaluateIPOnly() = %q, want %q", got, "blocked")
	}

	entry, err := hexwallStore.GetRecentFraudCheck("203.0.113.25")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry == nil || !entry.ShouldKill {
		t.Fatalf("GetRecentFraudCheck() = %+v, want cached ShouldKill = true", entry)
	}

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM killed_connections WHERE ip = ?`, "203.0.113.25"); got != 1 {
		t.Fatal("applyBlockedOutcome was not invoked for a live should-kill verdict")
	}
}

// NOTE: store.IsAllowed returning a hard error is not practically reachable with a
// real, healthy *store.Store — it only happens on a corrupted/closed DB handle, which
// would also break every other store call in the same scan. Not covered here; would
// require poking store internals from outside its package, which isn't a safe seam.

// ---- Scanner.Run -------------------------------------------------------------

func TestRunScanZeroConnections(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\necho '[]'\n")
	hexwallStore, _ := newTestStore(t)

	// Must not panic even with nil checker/deghost/zeek dependencies.
	(&Scanner{Store: hexwallStore, Mode: ModeWatch, ConnectionLister: connlist.GetEstablishedConnections}).Run(context.Background())
}

func TestRunScanFallsBackToSomoWhenConnectionListerUnset(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\necho '[]'\n")
	hexwallStore, _ := newTestStore(t)

	// Even when a caller forgets to populate the field, Run should still work.
	scanner := &Scanner{Store: hexwallStore, Mode: ModeWatch}
	scanner.Run(context.Background())
	if scanner.ConnectionLister == nil {
		t.Fatal("ConnectionLister fallback is nil after Run()")
	}
}

func TestRunScanAllowlistedConnectionSkipsIPFallback(t *testing.T) {
	installFakeSomo(t, `#!/bin/sh
echo '[{"proto":"tcp","local_port":"51820","remote_address":"127.0.0.1","remote_port":"443","program":"curl","pid":"1","state":"ESTABLISHED","address_type":"ipv4"}]'
`)
	hexwallStore, dbPath := newTestStore(t)

	(&Scanner{Store: hexwallStore, Mode: ModeWatch, ConnectionLister: connlist.GetEstablishedConnections}).Run(context.Background())

	// Rung 1 (static allowlist) short-circuits before the IP-only fallback, so
	// no ip_observations row should exist for a loopback address.
	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM ip_observations WHERE ip = ?`, "127.0.0.1"); got != 0 {
		t.Fatalf("ip_observations count for allowlisted ip = %d, want 0", got)
	}
}

func TestRunScanInvalidAddressDoesNotStopScan(t *testing.T) {
	installFakeSomo(t, `#!/bin/sh
echo '[{"proto":"tcp","local_port":"1","remote_address":"not-an-ip","remote_port":"443","program":"curl","pid":"1","state":"ESTABLISHED","address_type":"ipv4"},{"proto":"tcp","local_port":"2","remote_address":"203.0.113.30","remote_port":"443","program":"curl","pid":"2","state":"ESTABLISHED","address_type":"ipv4"}]'
`)
	hexwallStore, dbPath := newTestStore(t)

	(&Scanner{Store: hexwallStore, Mode: ModeWatch, ConnectionLister: connlist.GetEstablishedConnections}).Run(context.Background())

	// The second, valid connection must still be processed through the IP-only
	// fallback despite the first connection's address being unparsable.
	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM ip_observations WHERE ip = ?`, "203.0.113.30"); got != 1 {
		t.Fatalf("ip_observations count for valid ip after invalid entry = %d, want 1", got)
	}
}

func TestRunScanUnknownIPRecordsIPObservation(t *testing.T) {
	installFakeSomo(t, `#!/bin/sh
echo '[{"proto":"tcp","local_port":"1","remote_address":"203.0.113.31","remote_port":"443","program":"curl","pid":"1","state":"ESTABLISHED","address_type":"ipv4"}]'
`)
	hexwallStore, dbPath := newTestStore(t)

	(&Scanner{Store: hexwallStore, Mode: ModeWatch, ConnectionLister: connlist.GetEstablishedConnections}).Run(context.Background())

	if got := queryInt(t, dbPath, `SELECT COUNT(*) FROM ip_observations WHERE ip = ? AND outcome = 'unknown'`, "203.0.113.31"); got != 1 {
		t.Fatalf("ip_observations unknown count = %d, want 1", got)
	}
}

// NOTE on rung 2/3/4 (Zeek SNI -> Pi-hole allow/deny) coverage inside Scanner.Run:
// zeek.Client has no exported constructor or seam that lets an external package
// (monitor_test.go is package monitor, not package zeek) populate its SNI cache
// without going through the real background tailer, which only polls every 5s
// (zeek.tickInterval) with no synchronous first pass. Driving that path from here
// would mean sleeping 5+ seconds per test or poking zeek's unexported fields from
// outside its own package, neither of which fits the constraints for this task.
// Rungs 3/4 themselves (pihole.Checker.IsAllowedByPolicy / IsBlockedByPolicy) are
// exercised directly by internal/pihole's own tests, and HandleZeekEvent above
// exercises the same Checker.IsBlockedByPolicy call against a real gravity db.
