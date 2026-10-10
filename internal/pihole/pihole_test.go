package pihole

import (
	"net/url"
	"slices"
	"testing"
	"time"
)

func TestSQLiteReadOnlyDSNRelativePath(t *testing.T) {
	t.Parallel()

	dsn := "file:" + (&url.URL{Path: "./pihole-FTL.db", RawQuery: "mode=ro"}).String()
	want := "file:./pihole-FTL.db?mode=ro"
	if dsn != want {
		t.Fatalf("dsn = %q, want %q", dsn, want)
	}
}

func TestSQLiteReadOnlyDSNAbsolutePath(t *testing.T) {
	t.Parallel()

	dsn := "file:" + (&url.URL{Path: "/etc/pihole/pihole-FTL.db", RawQuery: "mode=ro"}).String()
	want := "file:/etc/pihole/pihole-FTL.db?mode=ro"
	if dsn != want {
		t.Fatalf("dsn = %q, want %q", dsn, want)
	}
}

// TestDomainsSeenSinceExcludesBlocked pins the trust-cache input: a domain Pi-hole blocked
// is still in the query log, and must not come back as a domain to resolve and trust.
// Statuses 2, 3 and 17 are the ones a real Pi-hole (FTL v6.7.1) logged for answered queries;
// 1 is what it logged for a gravity-blocked domain.
func TestDomainsSeenSinceExcludesBlocked(t *testing.T) {
	t.Parallel()

	checker := newTestChecker(t, "")
	now := time.Now().Unix()
	rows := []struct {
		domain string
		status int
	}{
		{"forwarded.example", 2},
		{"cached.example", 3},
		{"stale-cache.example", 17},
		{"gravity-blocked.example", 1},
		{"regex-blocked.example", 4},
		{"denylist-blocked.example", 5},
		{"cname-blocked.example", 9},
	}
	for _, r := range rows {
		if _, err := checker.db.Exec(
			`INSERT INTO queries (timestamp, type, domain, status) VALUES (?, 1, ?, ?)`,
			now, r.domain, r.status,
		); err != nil {
			t.Fatalf("insert %q: %v", r.domain, err)
		}
	}

	got, err := checker.DomainsSeenSince(now - 60)
	if err != nil {
		t.Fatalf("DomainsSeenSince() error: %v", err)
	}

	want := []string{"cached.example", "forwarded.example", "stale-cache.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("DomainsSeenSince() = %v, want %v", got, want)
	}
}
