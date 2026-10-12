package pihole

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

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

	log := &fakeQueryLog{now: time.Now()}
	log.clientAsks("example.com")
	log.clientAsks("example.org")
	cache := &IPCache{
		store:                hexwallStore,
		answeredQueriesAfter: log.answeredQueriesAfter,
		maxQueryID:           log.maxQueryID,
		now:                  func() time.Time { return log.now },
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

// fakeQueryLog stands in for Pi-hole's query log. When hexwall resolves through Pi-hole,
// its own lookups are logged too; lookupHost records them like Pi-hole would.
type fakeQueryLog struct {
	now     time.Time
	queries []AnsweredQuery
	lookups []string // domains hexwall resolved, in order
}

func (l *fakeQueryLog) clientAsks(domain string) {
	l.queries = append(l.queries, AnsweredQuery{ID: int64(len(l.queries) + 1), Domain: domain, Timestamp: l.now})
}

func (l *fakeQueryLog) answeredQueriesAfter(afterID, since int64) ([]AnsweredQuery, error) {
	var out []AnsweredQuery

	for _, q := range l.queries {
		if q.ID > afterID && q.Timestamp.Unix() >= since {
			out = append(out, q)
		}
	}

	return out, nil
}

func (l *fakeQueryLog) maxQueryID() (int64, error) {
	if len(l.queries) == 0 {
		return 0, nil
	}

	return l.queries[len(l.queries)-1].ID, nil
}

// lookupThroughPihole resolves like a host whose resolver is Pi-hole: the lookup is logged.
func (l *fakeQueryLog) lookupThroughPihole(_ context.Context, host string) ([]string, error) {
	l.lookups = append(l.lookups, host)
	l.clientAsks(host)

	return []string{"192.0.2.10"}, nil
}

func newFakeCache(t *testing.T, log *fakeQueryLog) *IPCache {
	t.Helper()

	hexwallStore, err := store.NewStore(filepath.Join(t.TempDir(), "hexwall.db"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	t.Cleanup(func() { _ = hexwallStore.Close() })

	return &IPCache{
		store:                hexwallStore,
		answeredQueriesAfter: log.answeredQueriesAfter,
		maxQueryID:           log.maxQueryID,
		lookupHost:           log.lookupThroughPihole,
		now:                  func() time.Time { return log.now },
	}
}

// The feedback loop: hexwall's lookup is logged by Pi-hole, and must not count as a client
// asking again, or every domain stays trusted forever.
func TestIPCacheRefreshIgnoresOwnLookups(t *testing.T) {
	log := &fakeQueryLog{now: time.Unix(1_800_000_000, 0)}
	cache := newFakeCache(t, log)

	log.clientAsks("example.com")

	for range 5 {
		cache.Refresh(context.Background())

		log.now = log.now.Add(30 * time.Second)
	}

	if want := []string{"example.com"}; !slices.Equal(log.lookups, want) {
		t.Fatalf("lookups = %q, want %q (one per client query)", log.lookups, want)
	}
}

func TestIPCacheRefreshResolvesRepeatClientQueries(t *testing.T) {
	log := &fakeQueryLog{now: time.Unix(1_800_000_000, 0)}
	cache := newFakeCache(t, log)

	log.clientAsks("example.com")
	cache.Refresh(context.Background())

	log.now = log.now.Add(time.Minute)
	log.clientAsks("example.com")
	cache.Refresh(context.Background())

	if want := []string{"example.com", "example.com"}; !slices.Equal(log.lookups, want) {
		t.Fatalf("lookups = %q, want %q", log.lookups, want)
	}
}

// "pihole flush" empties the log and restarts ids; queries after it must still be read.
func TestIPCacheRefreshAfterQueryLogReset(t *testing.T) {
	log := &fakeQueryLog{now: time.Unix(1_800_000_000, 0)}
	cache := newFakeCache(t, log)

	log.clientAsks("a.example")
	log.clientAsks("b.example")
	cache.Refresh(context.Background())

	log.queries = nil
	log.now = log.now.Add(time.Minute)
	log.clientAsks("c.example")
	cache.Refresh(context.Background())

	if !slices.Contains(log.lookups, "c.example") {
		t.Fatalf("lookups = %q, want c.example resolved after the reset", log.lookups)
	}
}
