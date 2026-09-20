package pihole

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hexbytedev/hexwall/internal/store"
)

func TestIPCacheRefreshWritesTrustedIPAndDomains(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")
	hexwallStore, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	cache := &IPCache{
		store: hexwallStore,
		domainsSeenSince: func(int64) ([]string, error) {
			return []string{"example.com", "example.org"}, nil
		},
		lookupHost: func(_ context.Context, host string) ([]string, error) {
			switch host {
			case "example.com":
				return []string{"93.184.216.34", "93.184.216.35"}, nil
			case "example.org":
				return []string{"93.184.216.34"}, nil
			default:
				return nil, nil
			}
		},
	}

	cache.Refresh(context.Background())

	allowed, err := hexwallStore.IsAllowed("93.184.216.34")
	if err != nil {
		t.Fatalf("IsAllowed() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsAllowed() = false, want true")
	}

	domains, err := hexwallStore.DomainsForIP("93.184.216.34")
	if err != nil {
		t.Fatalf("DomainsForIP() error = %v", err)
	}
	want := []string{"example.com", "example.org"}
	if !reflect.DeepEqual(domains, want) {
		t.Fatalf("DomainsForIP() = %v, want %v", domains, want)
	}
}
