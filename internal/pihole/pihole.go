// Package pihole handles all pihole related tasks.
package pihole

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// Config holds the configuration for the pihole checker.
type Config struct {
	DBPath string
}

// Checker is responsible for checking if a domain is known based on the pihole query history.
type Checker struct {
	db *sql.DB
}

// NewChecker creates a new Checker instance with the given configuration.
func NewChecker(config *Config) (*Checker, error) {
	// Pre-check: give an actionable error before SQLite gets a chance to emit
	// a generic "unable to open database file" message.
	if _, err := os.Open(config.DBPath); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf(
				"permission denied reading %s — try running with sudo or: sudo chmod o+r %s",
				config.DBPath, config.DBPath,
			)
		}

		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pihole-FTL.db not found at %s", config.DBPath)
		}
		return nil, fmt.Errorf("cannot access %s: %w", config.DBPath, err)
	}

	// db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&immutable=1", config.DBPath))
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", config.DBPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open pihole-db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to pihole-db: %w", err)
	}

	return &Checker{
		db: db,
	}, nil
}

// Close closes the database connection.
func (c *Checker) Close() error {
	return c.db.Close()
}

// IsDomainKnown checks if the given domain appeared in Pi-hole's query history
// in the last 60 minutes. If found, Pi-hole already decided its fate — let it through.
// If not found, it bypassed DNS entirely and should be treated as suspicious.
func (c *Checker) IsDomainKnown(domain string) (bool, error) {
	cutoff := time.Now().Add(-60 * time.Minute).Unix()

	query := `SELECT COUNT(*) FROM queries WHERE domain = ? AND timestamp >= ?`

	var count int
	err := c.db.QueryRow(query, domain, cutoff).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("database query failed: %w", err)
	}

	return count > 0, nil
}

// DomainsSeenSince returns all distinct domains Pi-hole has recorded since the given Unix timestamp.
func (c *Checker) DomainsSeenSince(since int64) ([]string, error) {
	rows, err := c.db.Query(`SELECT DISTINCT domain FROM queries WHERE timestamp >= ?`, since)
	if err != nil {
		return nil, fmt.Errorf("database query failed: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		domains = append(domains, domain)
	}

	return domains, rows.Err()
}
