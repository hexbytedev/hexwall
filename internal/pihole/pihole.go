// Package pihole reads query history from the Pi-hole FTL database.
// It exposes helpers for checking recent domains and building the trusted-IP cache.
package pihole

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	// Register the pure-Go SQLite driver used to read the Pi-hole FTL database.
	_ "modernc.org/sqlite"
)

// Config holds the Pi-hole database configuration.
type Config struct {
	DBPath        string
	GravityDBPath string // optional; derived from DBPath when empty
}

// Checker reads Pi-hole query history from the FTL database and policy lists from gravity.
type Checker struct {
	db        *sql.DB
	gravityDB *sql.DB

	// regex is swapped whole by RefreshRegexLists while scans read it from another goroutine.
	regex atomic.Pointer[regexLists]
}

const domainLookback = time.Hour

// NewChecker opens a read-only Checker for the configured Pi-hole database.
func NewChecker(config *Config) (*Checker, error) {
	if config == nil {
		return nil, errors.New("missing pihole config")
	}

	if strings.TrimSpace(config.DBPath) == "" {
		return nil, errors.New("missing pihole database path")
	}

	// Check file access first so SQLite does not hide permission problems behind a generic error.
	file, err := os.Open(config.DBPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf(
				"permission denied reading %s; try running with sudo or: sudo chmod o+r %s",
				config.DBPath, config.DBPath,
			)
		}

		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pihole-FTL.db not found at %s", config.DBPath)
		}

		return nil, fmt.Errorf("cannot access %s: %w", config.DBPath, err)
	}

	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close access check for %s: %w", config.DBPath, err)
	}

	dsn := "file:" + (&url.URL{Path: config.DBPath, RawQuery: "mode=ro"}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open pihole-db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to pihole-db: %w", err)
	}

	// Open gravity.db for policy list lookups.
	gravityPath := config.GravityDBPath
	if gravityPath == "" {
		gravityPath = filepath.Join(filepath.Dir(config.DBPath), "gravity.db")
	}

	var gravityDB *sql.DB
	if err := openGravityDB(gravityPath, &gravityDB); err != nil {
		slog.Warn("pi-hole gravity database unavailable; policy checks disabled",
			"path", gravityPath, "err", err)
	}

	checker := &Checker{
		db:        db,
		gravityDB: gravityDB,
	}
	if err := checker.RefreshRegexLists(); err != nil {
		slog.Warn("pi-hole regex lists unavailable; only exact-match policy checks apply", "err", err)
	}

	return checker, nil
}

// openGravityDB opens the Pi-hole gravity database in read-only mode.
// On success it sets *out; on failure it returns an error but does not touch *out.
func openGravityDB(path string, out **sql.DB) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", path, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close access check for %s: %w", path, err)
	}

	dsn := "file:" + (&url.URL{Path: path, RawQuery: "mode=ro"}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open gravity-db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to connect to gravity-db: %w", err)
	}

	*out = db

	return nil
}

// Close closes both database connections.
func (c *Checker) Close() error {
	if c == nil {
		return nil
	}

	var (
		errFTL     error
		errGravity error
	)

	if c.db != nil {
		errFTL = c.db.Close()
	}

	if c.gravityDB != nil {
		errGravity = c.gravityDB.Close()
	}

	return errors.Join(errFTL, errGravity)
}

// IsDomainKnown reports whether domain appeared in Pi-hole query history within the last hour.
// Domains missing from that history bypassed Pi-hole DNS resolution and are treated as suspicious.
func (c *Checker) IsDomainKnown(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}

	cutoff := time.Now().Add(-domainLookback).Unix()

	var found int

	err := c.db.QueryRow(`
		SELECT 1
		FROM queries
		WHERE timestamp >= ?
		  AND TRIM(domain) <> ''
		  AND domain = ? COLLATE NOCASE
		LIMIT 1
	`, cutoff, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("database query failed: %w", err)
	}

	return true, nil
}

// IsAllowedByPolicy reports whether the domain is on Pi-hole's allowlist or matches an allow regex.
func (c *Checker) IsAllowedByPolicy(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}

	if c == nil || c.gravityDB == nil {
		return false, nil
	}

	var found int

	err := c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_allowlist
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return c.matchesRegex(domain, true), nil
	}

	if err != nil {
		return false, fmt.Errorf("allowlist lookup failed: %w", err)
	}

	return true, nil
}

// IsBlockedByPolicy reports whether the domain is on Pi-hole's denylist or gravity, or matches a deny regex.
func (c *Checker) IsBlockedByPolicy(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}

	if c == nil || c.gravityDB == nil {
		return false, nil
	}

	var found int

	err := c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_denylist
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if err == nil {
		return true, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("denylist lookup failed: %w", err)
	}

	err = c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_gravity
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return c.matchesRegex(domain, false), nil
	}

	if err != nil {
		return false, fmt.Errorf("gravity lookup failed: %w", err)
	}

	return true, nil
}

// PolicyCounts returns the number of entries in each Pi-hole policy view.
// The returned map is keyed by view name. Returns nil if gravity DB is unavailable.
func (c *Checker) PolicyCounts() (map[string]int64, error) {
	if c == nil || c.gravityDB == nil {
		return nil, nil
	}

	views := []string{"vw_allowlist", "vw_denylist", "vw_gravity", "vw_regex_allowlist", "vw_regex_denylist"}
	counts := make(map[string]int64, len(views))

	for _, view := range views {
		var count int64

		err := c.gravityDB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, view)).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", view, err)
		}

		counts[view] = count
	}

	return counts, nil
}

// answeredStatuses lists the FTL query status codes that count as "Pi-hole answered this
// domain". Only these feed the trusted-IP cache. A blocked query is still written to the
// query log, and without this filter its domain would be re-resolved by the host's own
// resolver and its real IP trusted -- blocking a domain would end up trusting it.
// Status codes: https://docs.pi-hole.net/database/query-database/#query-status
//
// This is an allow-list on purpose: a status code added by a future FTL release is
// untrusted until it is reviewed here, rather than silently trusted.
var answeredStatuses = []int{
	2,  // forwarded to upstream
	3,  // answered from cache
	12, // retried
	13, // retried, but ignored
	14, // already forwarded
	17, // answered from stale cache
}

// AnsweredQuery is one query from Pi-hole's log that Pi-hole answered.
type AnsweredQuery struct {
	ID        int64
	Domain    string
	Timestamp time.Time
}

// AnsweredQueriesAfter returns the queries Pi-hole answered with an id above afterID and a
// timestamp at or after since (Unix seconds), in id order. Queries Pi-hole blocked are
// excluded; see answeredStatuses.
func (c *Checker) AnsweredQueriesAfter(afterID, since int64) ([]AnsweredQuery, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(answeredStatuses)), ",")
	args := make([]any, 0, len(answeredStatuses)+2)

	args = append(args, afterID, since)
	for _, status := range answeredStatuses {
		args = append(args, status)
	}

	rows, err := c.db.Query(fmt.Sprintf(`
		SELECT id, LOWER(TRIM(domain)), timestamp
		FROM queries
		WHERE id > ?
		  AND timestamp >= ?
		  AND domain IS NOT NULL
		  AND TRIM(domain) <> ''
		  AND status IN (%s)
		ORDER BY id
	`, placeholders), args...)
	if err != nil {
		return nil, fmt.Errorf("database query failed: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var queries []AnsweredQuery

	for rows.Next() {
		var q AnsweredQuery

		var timestamp float64 // FTL v6 stores fractional seconds
		if err := rows.Scan(&q.ID, &q.Domain, &timestamp); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		q.Timestamp = time.Unix(0, int64(timestamp*float64(time.Second)))
		queries = append(queries, q)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return queries, nil
}

// MaxQueryID returns the highest id in Pi-hole's query log, or 0 when it is empty. It drops
// below an id seen earlier only when the log was flushed or recreated.
func (c *Checker) MaxQueryID() (int64, error) {
	var maxID sql.NullInt64
	if err := c.db.QueryRow(`SELECT MAX(id) FROM queries`).Scan(&maxID); err != nil {
		return 0, fmt.Errorf("database query failed: %w", err)
	}

	return maxID.Int64, nil
}

// DomainMatches reports whether an observed SNI domain corresponds to a known domain,
// treating a subdomain as a match for its parent in either direction.
//
// The direction is intentionally symmetric: Zeek reports the SNI exactly as sent on the wire
// (www.github.com) while the store holds whatever Pi-hole logged and the cache resolved
// (github.com), and either can be the more specific name.
//
// The match requires a label boundary, so github.com.evil.com does not match github.com:
// it does not end in ".github.com". A plain suffix test would have accepted it.
//
// A registrable-domain (eTLD+1) comparison via golang.org/x/net/publicsuffix would handle more
// edge cases -- notably unrelated names under a shared public suffix -- but it adds a third-party
// dependency for a marginal gain, so the label-boundary rule is the deliberate v1 tradeoff.
func DomainMatches(observed, known string) bool {
	observed = normalizeDomain(observed)
	known = normalizeDomain(known)

	if observed == "" || known == "" {
		return false
	}

	if observed == known {
		return true
	}

	return strings.HasSuffix(observed, "."+known) || strings.HasSuffix(known, "."+observed)
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}
