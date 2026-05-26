// Package store manages the local pihole-guard SQLite database.
// Unlike the Pi-hole DB, this database is owned by the tool
// and persists trusted IPs and kill logs across restarts.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS allowed_ips (
    ip               TEXT    PRIMARY KEY,
    domain           TEXT    NOT NULL,
    first_approved   INTEGER NOT NULL,
    last_refreshed   INTEGER NOT NULL,
    last_established INTEGER
);

CREATE TABLE IF NOT EXISTS killed_connections (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL,
    pid       TEXT    NOT NULL,
    program   TEXT    NOT NULL,
    killed_at INTEGER NOT NULL
);
`

// Store wraps the local guard database.
type Store struct {
	readWrite *sql.DB
	readOnly  *sql.DB
}

// NewStore opens or creates the guard database at dbPath and applies the schema.
func NewStore(dbPath string) (*Store, error) {
	readWrite, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=rwc", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open guard db: %w", err)
	}

	if err := configureConnection(readWrite); err != nil {
		readWrite.Close()
		return nil, fmt.Errorf("failed to connect to guard db: %w", err)
	}

	if _, err := readWrite.Exec(schema); err != nil {
		readWrite.Close()
		return nil, fmt.Errorf("failed to apply schema: %w", err)
	}

	readOnly, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", dbPath))
	if err != nil {
		readWrite.Close()
		return nil, fmt.Errorf("failed to open guard db read-only connection: %w", err)
	}

	if err := configureConnection(readOnly); err != nil {
		readOnly.Close()
		readWrite.Close()
		return nil, fmt.Errorf("failed to connect to guard db read-only connection: %w", err)
	}

	return &Store{readWrite: readWrite, readOnly: readOnly}, nil
}

func configureConnection(db *sql.DB) error {
	if err := db.Ping(); err != nil {
		return err
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return fmt.Errorf("set journal_mode WAL: %w", err)
	}

	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		return fmt.Errorf("set busy_timeout: %w", err)
	}

	return nil
}

// Close closes both database connections.
func (s *Store) Close() error {
	var errReadWrite error
	var errReadOnly error

	if s.readWrite != nil {
		errReadWrite = s.readWrite.Close()
	}

	if s.readOnly != nil {
		errReadOnly = s.readOnly.Close()
	}

	return errors.Join(errReadWrite, errReadOnly)
}

// UpsertAllowedIP inserts or refreshes a trusted IP.
// On conflict, it updates the domain and last_refreshed while preserving first_approved and last_established.
func (s *Store) UpsertAllowedIP(ip, domain string) error {
	now := time.Now().Unix()

	_, err := s.readWrite.Exec(`
		INSERT INTO allowed_ips (ip, domain, first_approved, last_refreshed)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			domain        = excluded.domain,
			last_refreshed = excluded.last_refreshed
	`, ip, domain, now, now)

	if err != nil {
		return fmt.Errorf("upsert allowed ip %s: %w", ip, err)
	}

	return nil
}

// UpdateEstablished stamps the current time as last_established for an IP.
// The monitor calls it when somo confirms the connection is still active.
func (s *Store) UpdateEstablished(ip string) error {
	_, err := s.readWrite.Exec(`
		UPDATE allowed_ips SET last_established = ? WHERE ip = ?
	`, time.Now().Unix(), ip)

	if err != nil {
		return fmt.Errorf("update established %s: %w", ip, err)
	}

	return nil
}

// IsAllowed reports whether the IP is trusted based on a recent Pi-hole refresh or recent established-connection activity.
//
// It returns true if the IP is trusted. An IP is trusted when either:
//   - It was refreshed from Pi-hole's domain history within the last hour, OR
//   - somo confirmed it as an active established connection within the last 60 seconds
//     (keeps long-running connections alive even after their domain ages out)
func (s *Store) IsAllowed(ip string) (bool, error) {
	now := time.Now().Unix()
	refreshCutoff := now - 3600   // 1 hour
	establishedCutoff := now - 60 // 60 seconds

	var found int
	err := s.readOnly.QueryRow(`
		SELECT 1 FROM allowed_ips
		WHERE ip = ?
		  AND (last_refreshed   >= ?
		    OR last_established >= ?)
		LIMIT 1
	`, ip, refreshCutoff, establishedCutoff).Scan(&found)

	if err == sql.ErrNoRows {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("is allowed query for %s: %w", ip, err)
	}

	return true, nil
}

// LogKill records a killed connection in the audit log.
func (s *Store) LogKill(ip, pid, program string) error {
	_, err := s.readWrite.Exec(`
		INSERT INTO killed_connections (ip, pid, program, killed_at)
		VALUES (?, ?, ?, ?)
	`, ip, pid, program, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("log kill %s: %w", ip, err)
	}

	return nil
}
