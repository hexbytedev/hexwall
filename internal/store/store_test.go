package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteDSNRelativePath(t *testing.T) {
	t.Parallel()

	dsn := sqliteDSN("./pihole-guard.db", "rwc")
	want := "file:./pihole-guard.db?mode=rwc"
	if dsn != want {
		t.Fatalf("sqliteDSN() = %q, want %q", dsn, want)
	}
}

func TestSQLiteDSNAbsolutePath(t *testing.T) {
	t.Parallel()

	dsn := sqliteDSN("/tmp/pihole-guard.db", "ro")
	want := "file:/tmp/pihole-guard.db?mode=ro"
	if dsn != want {
		t.Fatalf("sqliteDSN() = %q, want %q", dsn, want)
	}
}

func TestFraudCheckCacheRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	guardStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := guardStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	entry, err := guardStore.GetRecentFraudCheck("203.0.113.10")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentFraudCheck() = %#v, want nil before insert", entry)
	}

	if err := guardStore.UpsertFraudCheck("203.0.113.10", true); err != nil {
		t.Fatalf("UpsertFraudCheck() error = %v", err)
	}

	entry, err = guardStore.GetRecentFraudCheck("203.0.113.10")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() after insert error = %v", err)
	}
	if entry == nil {
		t.Fatal("GetRecentFraudCheck() = nil, want cached entry")
	}
	if !entry.ShouldKill {
		t.Fatal("GetRecentFraudCheck().ShouldKill = false, want true")
	}
	if entry.CheckedAt <= 0 {
		t.Fatalf("GetRecentFraudCheck().CheckedAt = %d, want positive unix timestamp", entry.CheckedAt)
	}
}

func TestFraudCheckCacheExpiresAfterWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	guardStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := guardStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	staleCheckedAt := time.Now().Add(-fraudCheckCacheWindow - time.Minute).Unix()
	if _, err := guardStore.readWrite.Exec(`
		INSERT INTO fraud_checks (ip, should_kill, checked_at)
		VALUES (?, ?, ?)
	`, "203.0.113.20", 0, staleCheckedAt); err != nil {
		t.Fatalf("insert stale fraud check error = %v", err)
	}

	entry, err := guardStore.GetRecentFraudCheck("203.0.113.20")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentFraudCheck() = %#v, want nil for stale entry", entry)
	}
}
