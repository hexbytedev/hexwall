// Package allowlist defines CIDRs that are always trusted and never killed.
// These are IPs that legitimately bypass DNS (loopback, private ranges, cloud metadata).
package allowlist

import (
	"log/slog"
	"net"
	"strings"
)

var cidrs = []string{
	"127.0.0.0/8",        // loopback IPv4
	"::1/128",            // loopback IPv6
	"10.0.0.0/8",         // private
	"172.16.0.0/12",      // private
	"192.168.0.0/16",     // private
	"169.254.169.254/32", // cloud metadata endpoint
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

// Contains reports whether ip matches any allowlisted CIDR.
func Contains(ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
