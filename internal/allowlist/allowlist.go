// Package allowlist defines statically trusted IP networks in CIDR notation.
// These networks bypass runtime reputation checks because they cover loopback,
// private-use space, and the link-local cloud metadata endpoint.
package allowlist

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

var cidrs = []string{
	"127.0.0.0/8",        // entire IPv4 loopback block
	"::1/128",            // single IPv6 loopback address
	"10.0.0.0/8",         // RFC 1918 private-use block
	"172.16.0.0/12",      // RFC 1918 private-use block
	"192.168.0.0/16",     // RFC 1918 private-use block
	"169.254.169.254/32", // link-local cloud metadata endpoint
}

var nets []*net.IPNet

func init() {
	loadCIDRs(cidrs)
}

func loadCIDRs(values []string) {
	for _, value := range values {
		net, err := parseCIDR(value)
		if err != nil {
			slog.Error("failed to parse allowlist CIDRs", "err", err)
			continue
		}
		nets = append(nets, net)
	}
}

func parseCIDR(value string) (*net.IPNet, error) {
	cidr := strings.TrimSpace(value)

	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %q", value)
		}
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP or CIDR: %q", value)
	}

	return network, nil
}

// Contains reports whether ip belongs to any statically trusted CIDR.
func Contains(ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
