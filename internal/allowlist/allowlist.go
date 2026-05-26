// Package allowlist defines statically trusted IP networks in CIDR notation.
// These networks bypass runtime reputation checks because they cover loopback,
// private-use space, and the link-local cloud metadata endpoint.
package allowlist

import (
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
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Error("invalid allowlist entry", "cidr", cidr, "err", err)
			continue
		}

		nets = append(nets, network)
	}
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
