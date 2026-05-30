package pihole

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hexbytedev/hexwall/internal/store"
)

const (
	refreshLookback      = time.Hour
	lookupTimeout        = time.Second
	maxConcurrentLookups = 32
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

// Refresh queries Pi-hole for recent domains, resolves them with bounded concurrency,
// and upserts the resulting unique IPs into the store.
func (c *IPCache) Refresh(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	since := time.Now().Add(-refreshLookback).Unix()

	domains, err := c.checker.DomainsSeenSince(since)
	if err != nil {
		slog.Error("cache refresh: failed to query pi-hole domains", "err", err)
		return
	}
	if len(domains) == 0 {
		slog.Info("cache refreshed", "domains", 0, "ips", 0)
		return
	}

	sort.Strings(domains)

	type result struct {
		domain string
		ips    []string
	}
	results := make(chan result, maxConcurrentLookups)
	sem := make(chan struct{}, maxConcurrentLookups)

	var wg sync.WaitGroup
spawnLoop:
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			break spawnLoop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			rctx, cancel := context.WithTimeout(ctx, lookupTimeout)
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

	resolved := make(map[string][]string, len(domains))
	for r := range results {
		resolved[r.domain] = r.ips
	}

	if ctx.Err() != nil {
		return
	}

	// The store keeps one domain per IP, so keep the first domain in a stable order.
	uniqueIPs := make(map[string]string, len(resolved))
	for _, domain := range domains {
		ips, ok := resolved[domain]
		if !ok {
			continue
		}

		for _, ip := range ips {
			if _, exists := uniqueIPs[ip]; exists {
				continue
			}
			uniqueIPs[ip] = domain
		}
	}

	var totalIPs int
	for ip, domain := range uniqueIPs {
		if err := c.store.UpsertAllowedIP(ip, domain); err != nil {
			slog.Error("cache refresh: failed to upsert IP", "ip", ip, "domain", domain, "err", err)
		} else {
			totalIPs++
		}
	}

	slog.Info("cache refreshed", "domains", len(domains), "ips", totalIPs)
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
