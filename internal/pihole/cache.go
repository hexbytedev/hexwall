package pihole

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hexbytedev/pihole-guard/internal/store"
)

// IPCache resolves Pi-hole domains to IPs and writes them to the store.
// The store owns the trusted-IP set, and this type only drives the refresh cycle.
type IPCache struct {
	checker *Checker
	store   *store.Store
}

// NewIPCache creates an IPCache backed by the given Checker and Store.
func NewIPCache(checker *Checker, store *store.Store) *IPCache {
	return &IPCache{
		checker: checker,
		store:   store,
	}
}

// Refresh queries Pi-hole for domains seen in the last hour, resolves them concurrently, and upserts the resulting IPs into the store.
func (c *IPCache) Refresh(ctx context.Context) {
	since := time.Now().Add(-60 * time.Minute).Unix()

	domains, err := c.checker.DomainsSeenSince(since)
	if err != nil {
		slog.Error("cache refresh: failed to query pi-hole domains", "err", err)
		return
	}

	type result struct {
		domain string
		ips    []string
	}
	results := make(chan result, len(domains))

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, 1*time.Second)
			defer cancel()

			ips, err := net.DefaultResolver.LookupHost(rctx, d)
			if err != nil {
				// DNS failure is normal for blocked domains, expired records, and similar cases.
				return
			}
			results <- result{domain: d, ips: ips}
		}(domain)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var totalIPs int
	for r := range results {
		for _, ip := range r.ips {
			if err := c.store.UpsertAllowedIP(ip, r.domain); err != nil {
				slog.Error("cache refresh: failed to upsert IP", "ip", ip, "domain", r.domain, "err", err)
			} else {
				totalIPs++
			}
		}
	}

	slog.Info("cache refreshed", "domains", len(domains), "ips", totalIPs)
}

// RunRefresh calls Refresh immediately, then on the given interval until ctx is cancelled.
func (c *IPCache) RunRefresh(ctx context.Context, interval time.Duration) {
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
