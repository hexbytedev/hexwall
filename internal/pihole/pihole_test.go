package pihole

import (
	"net/url"
	"testing"
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
