package store

import "testing"

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
