package pihole

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/hexbytedev/hexwall/internal/store"
)

const (
	refreshLookback      = time.Hour
	lookupTimeout        = time.Second
	maxConcurrentLookups = 32

	// hexwall's own lookups go through the host resolver, which may be Pi-hole, so they land
	// in the query log hexwall reads. A logged query for a domain hexwall looked up within
	// this margin of its lookup is treated as that lookup's echo.
	ownLookupSlack = 2 * time.Second
	// How long to remember a lookup. FTL writes its log to disk about once a minute, so an
	// echo can show up well after the lookup itself.
	ownLookupMemory = 10 * time.Minute
)

// IPCache resolves the domains Pi-hole answered to IPs and writes them to the store.
// The store owns the trusted-IP set, and this type only drives the refresh cycle.
//
// Each logged query is read once, by id, so a domain's IPs are trusted for refreshLookback
// after a client last asked for it. Re-resolving every recent domain on each refresh
// instead would, through a host that uses Pi-hole, log a new query per domain every
// refresh and keep every domain "recent" forever.
type IPCache struct {
	checker *Checker
	store   *store.Store

	answeredQueriesAfter func(afterID, since int64) ([]AnsweredQuery, error)
	maxQueryID           func() (int64, error)
	lookupHost           func(context.Context, string) ([]string, error)
	now                  func() time.Time

	mu         sync.Mutex
	lastID     int64                // highest query id already read
	ownLookups map[string]time.Time // domain -> when hexwall last resolved it
}

// NewIPCache creates an IPCache backed by the given Checker and Store.
func NewIPCache(checker *Checker, store *store.Store) *IPCache {
	return &IPCache{
		checker:              checker,
		store:                store,
		answeredQueriesAfter: checker.AnsweredQueriesAfter,
		maxQueryID:           checker.MaxQueryID,
		lookupHost:           net.DefaultResolver.LookupHost,
		now:                  time.Now,
	}
}

// Refresh reads the queries Pi-hole answered since the last refresh, resolves their
// domains with bounded concurrency, and upserts the resulting unique IPs into the store.
func (c *IPCache) Refresh(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	domains, err := c.newClientDomains()
	if err != nil {
		slog.Error("cache refresh: failed to query pi-hole domains", "err", err)
		return
	}

	if len(domains) == 0 {
		slog.Debug("cache refreshed", "domains", 0, "ips", 0)
		return
	}

	sem := make(chan struct{}, maxConcurrentLookups)

	// Workers write straight into resolved under mu. Using a shared map instead of a
	// results channel keeps a worker from ever blocking on a consumer that has not
	// started yet, which would otherwise pin its slot in sem and stall the spawn loop.
	var mu sync.Mutex

	resolved := make(map[string][]string, len(domains))

	var wg sync.WaitGroup

	for _, domain := range domains {
		select {
		case <-ctx.Done():
		case sem <- struct{}{}:
		}

		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			rctx, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()

			mu.Lock()
			c.ownLookups[d] = c.now()
			mu.Unlock()

			ips, err := c.lookupHost(rctx, d)
			if err != nil {
				// DNS failure is normal for blocked domains, expired records, and similar cases.
				return
			}

			mu.Lock()
			resolved[d] = ips
			mu.Unlock()
		}(domain)
	}

	wg.Wait()

	if ctx.Err() != nil {
		return
	}

	// A shared CDN edge IP serves many unrelated domains, so keep the full set per IP.
	// domains is sorted, so each IP's slice stays in a stable order and its first entry
	// is the one recorded as the representative domain in allowed_ips.
	ipDomains := make(map[string][]string, len(resolved))

	seen := make(map[string]struct{}, len(resolved))
	for _, domain := range domains {
		ips, ok := resolved[domain]
		if !ok {
			continue
		}

		for _, ip := range ips {
			key := ip + "\x00" + domain
			if _, exists := seen[key]; exists {
				continue
			}

			seen[key] = struct{}{}

			ipDomains[ip] = append(ipDomains[ip], domain)
		}
	}

	var (
		totalIPs   int
		totalPairs int
	)

	for ip, ipDomainSet := range ipDomains {
		if err := c.store.UpsertAllowedIP(ip, ipDomainSet[0]); err != nil {
			slog.Error("cache refresh: failed to upsert IP", "ip", ip, "domain", ipDomainSet[0], "err", err)
		} else {
			totalIPs++
		}

		for _, domain := range ipDomainSet {
			if err := c.store.UpsertAllowedIPDomain(ip, domain); err != nil {
				slog.Error("cache refresh: failed to upsert IP domain", "ip", ip, "domain", domain, "err", err)
			} else {
				totalPairs++
			}
		}
	}

	slog.Info("cache refreshed", "domains", len(domains), "ips", totalIPs, "pairs", totalPairs)
}

// newClientDomains returns, sorted and without duplicates, the domains in queries logged
// since the last call, leaving out the echoes of hexwall's own lookups.
func (c *IPCache) newClientDomains() ([]string, error) {
	now := c.now()
	if c.ownLookups == nil {
		c.ownLookups = make(map[string]time.Time)
	}

	for domain, at := range c.ownLookups {
		if now.Sub(at) > ownLookupMemory {
			delete(c.ownLookups, domain)
		}
	}

	maxID, err := c.maxQueryID()
	if err != nil {
		return nil, err
	}

	if maxID < c.lastID {
		slog.Info("cache refresh: pi-hole query log was reset; re-reading the last hour")

		c.lastID = 0
	}

	queries, err := c.answeredQueriesAfter(c.lastID, now.Add(-refreshLookback).Unix())
	if err != nil {
		return nil, err
	}

	var domains []string

	for _, q := range queries {
		c.lastID = max(c.lastID, q.ID)
		if c.isOwnLookup(q) {
			continue
		}

		domains = append(domains, q.Domain)
	}

	slices.Sort(domains)

	return slices.Compact(domains), nil
}

// isOwnLookup reports whether q was logged when hexwall itself resolved q.Domain. A client
// that asked for the same domain in that same moment is skipped too, which costs nothing:
// hexwall's lookup has just refreshed that domain's IPs.
func (c *IPCache) isOwnLookup(q AnsweredQuery) bool {
	at, ok := c.ownLookups[q.Domain]
	if !ok {
		return false
	}

	return !q.Timestamp.Before(at.Add(-ownLookupSlack)) &&
		!q.Timestamp.After(at.Add(lookupTimeout+ownLookupSlack))
}

// RunRefresh calls Refresh on the given interval until ctx is cancelled.
func (c *IPCache) RunRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		slog.Error("cache refresh: invalid interval", "interval", interval)
		return
	}

	c.Refresh(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Refresh(ctx)
		}
	}
}
