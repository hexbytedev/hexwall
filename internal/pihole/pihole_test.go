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

// TestAnsweredQueriesAfterExcludesBlocked pins the trust-cache input: a domain Pi-hole blocked
// is still in the query log, and must not come back as a domain to resolve and trust.
// Statuses 2, 3 and 17 are the ones a real Pi-hole (FTL v6.7.1) logged for answered queries;
// 1 is what it logged for a gravity-blocked domain.
func TestAnsweredQueriesAfterExcludesBlocked(t *testing.T) {
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

	queries, err := checker.AnsweredQueriesAfter(0, now-60)
	if err != nil {
		t.Fatalf("AnsweredQueriesAfter() error: %v", err)
	}
	var got []string
	for _, q := range queries {
		got = append(got, q.Domain)
	}

	want := []string{"forwarded.example", "cached.example", "stale-cache.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("AnsweredQueriesAfter() domains = %v, want %v", got, want)
	}

	// The cursor: nothing after the last id read.
	maxID, err := checker.MaxQueryID()
	if err != nil {
		t.Fatalf("MaxQueryID() error: %v", err)
	}
	if rest, err := checker.AnsweredQueriesAfter(maxID, now-60); err != nil || len(rest) != 0 {
		t.Fatalf("AnsweredQueriesAfter(MaxQueryID()) = %v, %v; want none", rest, err)
	}
}
