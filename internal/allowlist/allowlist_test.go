package allowlist

import (
	"net"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	testCases := []struct {
		name      string
		value     string
		wantCIDR  string
		wantErr   string
		contains  []string
		notInCIDR []string
	}{
		{
			name:      "parses ipv4 cidr",
			value:     "10.0.0.0/8",
			wantCIDR:  "10.0.0.0/8",
			contains:  []string{"10.0.0.0", "10.1.2.3", "10.255.255.255"},
			notInCIDR: []string{"11.0.0.0"},
		},
		{
			name:      "parses ipv6 cidr",
			value:     "::1/128",
			wantCIDR:  "::1/128",
			contains:  []string{"::1"},
			notInCIDR: []string{"::2"},
		},
		{
			name:      "normalizes bare ipv4 address",
			value:     "8.8.8.8",
			wantCIDR:  "8.8.8.8/32",
			contains:  []string{"8.8.8.8"},
			notInCIDR: []string{"8.8.4.4"},
		},
		{
			name:      "normalizes bare ipv6 address",
			value:     "2001:4860:4860::8888",
			wantCIDR:  "2001:4860:4860::8888/128",
			contains:  []string{"2001:4860:4860::8888"},
			notInCIDR: []string{"2001:4860:4860::8844"},
		},
		{
			name:     "trims surrounding whitespace",
			value:    "\t192.168.1.0/24\n",
			wantCIDR: "192.168.1.0/24",
		},
		{
			name:    "rejects invalid bare ip",
			value:   "not-an-ip",
			wantErr: "invalid IP or CIDR: \"not-an-ip\"",
		},
		{
			name:    "rejects invalid cidr mask",
			value:   "127.0.0.1/99",
			wantErr: "invalid IP or CIDR: \"127.0.0.1/99\"",
		},
		{
			name:    "rejects whitespace only value",
			value:   "   ",
			wantErr: "invalid IP or CIDR: \"   \"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCIDR(tc.value)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseCIDR(%q) error = nil, want %q", tc.value, tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("parseCIDR(%q) error = %q, want %q", tc.value, err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseCIDR(%q) error = %v", tc.value, err)
			}

			if got == nil {
				t.Fatalf("parseCIDR(%q) = nil, want %q", tc.value, tc.wantCIDR)
			}

			if got.String() != tc.wantCIDR {
				t.Fatalf("parseCIDR(%q) = %q, want %q", tc.value, got.String(), tc.wantCIDR)
			}

			for _, ipText := range tc.contains {
				ip := net.ParseIP(ipText)
				if ip == nil {
					t.Fatalf("net.ParseIP(%q) = nil", ipText)
				}
				if !got.Contains(ip) {
					t.Fatalf("network %q does not contain %q", got.String(), ipText)
				}
			}

			for _, ipText := range tc.notInCIDR {
				ip := net.ParseIP(ipText)
				if ip == nil {
					t.Fatalf("net.ParseIP(%q) = nil", ipText)
				}
				if got.Contains(ip) {
					t.Fatalf("network %q unexpectedly contains %q", got.String(), ipText)
				}
			}
		})
	}
}

func TestLoadCIDRs(t *testing.T) {
	testCases := []struct {
		name      string
		values    []string
		wantCIDRs []string
	}{
		{
			name:      "loads built in cidrs",
			values:    cidrs,
			wantCIDRs: []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.169.254/32"},
		},
		{
			name:      "skips invalid entries and keeps valid ones",
			values:    []string{"10.0.0.0/8", "not-an-ip", "::1", "127.0.0.1/99", "169.254.169.254"},
			wantCIDRs: []string{"10.0.0.0/8", "::1/128", "169.254.169.254/32"},
		},
		{
			name:      "keeps existing nets and appends new ones",
			values:    []string{"::1"},
			wantCIDRs: []string{"127.0.0.0/8", "::1/128"},
		},
	}

	originalNets := nets
	defer func() {
		nets = originalNets
	}()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nets = nil
			if tc.name == "keeps existing nets and appends new ones" {
				existing, err := parseCIDR("127.0.0.0/8")
				if err != nil {
					t.Fatalf("parseCIDR(existing) error = %v", err)
				}
				nets = []*net.IPNet{existing}
			}

			loadCIDRs(tc.values)

			if len(nets) != len(tc.wantCIDRs) {
				t.Fatalf("len(nets) = %d, want %d", len(nets), len(tc.wantCIDRs))
			}

			for i, wantCIDR := range tc.wantCIDRs {
				if nets[i] == nil {
					t.Fatalf("nets[%d] = nil, want %q", i, wantCIDR)
				}
				if nets[i].String() != wantCIDR {
					t.Fatalf("nets[%d] = %q, want %q", i, nets[i].String(), wantCIDR)
				}
			}
		})
	}
}

func TestContains(t *testing.T) {
	originalNets := nets
	defer func() {
		nets = originalNets
	}()

	nets = nil
	loadCIDRs([]string{"10.0.0.0/8", "::1", "169.254.169.254"})

	testCases := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{
			name: "ipv4 inside network",
			ip:   net.ParseIP("10.1.2.3"),
			want: true,
		},
		{
			name: "ipv4 outside network",
			ip:   net.ParseIP("11.0.0.1"),
			want: false,
		},
		{
			name: "ipv6 exact host match",
			ip:   net.ParseIP("::1"),
			want: true,
		},
		{
			name: "ipv6 different host",
			ip:   net.ParseIP("::2"),
			want: false,
		},
		{
			name: "single host ipv4 exact match",
			ip:   net.ParseIP("169.254.169.254"),
			want: true,
		},
		{
			name: "single host ipv4 non match",
			ip:   net.ParseIP("169.254.169.253"),
			want: false,
		},
		{
			name: "nil ip",
			ip:   nil,
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Contains(tc.ip)
			if got != tc.want {
				t.Fatalf("Contains(%v) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestContainsWithNoNetworks(t *testing.T) {
	originalNets := nets
	nets = nil
	defer func() {
		nets = originalNets
	}()

	if Contains(net.ParseIP("127.0.0.1")) {
		t.Fatal("Contains returned true with empty allowlist")
	}
}
