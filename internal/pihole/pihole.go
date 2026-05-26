// Package pihole reads query history from the Pi-hole FTL database.
// It exposes helpers for checking recent domains and building the trusted-IP cache.
package pihole

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// Config holds the Pi-hole database configuration.
type Config struct {
	DBPath string
}

// Checker reads Pi-hole query history from the FTL database.
type Checker struct {
	db *sql.DB
}

// NewChecker opens a read-only Checker for the configured Pi-hole database.
func NewChecker(config *Config) (*Checker, error) {
	// Check file access first so SQLite does not hide permission problems behind a generic error.
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

// Close closes the Checker database connection.
func (c *Checker) Close() error {
	return c.db.Close()
}

// IsDomainKnown reports whether domain appeared in Pi-hole query history within the last hour.
// Domains missing from that history bypassed Pi-hole DNS resolution and are treated as suspicious.
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

// DomainsSeenSince returns the distinct domains Pi-hole recorded since the given Unix timestamp.
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
