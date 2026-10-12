package connlist

import (
	"os"
	"path/filepath"
	"testing"
)

// installFakeSS writes an executable shell script named "ss" into a temp
// directory and prepends it to PATH, mirroring installFakeSomo below and the
// same trick used in internal/enforcer/enforcer_socket_test.go.
func installFakeSS(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()

	path := filepath.Join(dir, "ss")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ss: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// realSSFixture is real `ss -H -tnp state established` output captured on a
// live Linux box (iproute2-6.1.0), used verbatim so the parser is validated
// against actual formatting rather than assumed grammar.
const realSSFixture = `0      0      192.168.0.223:53404   160.79.104.10:443  users:(("claude",pid=6039,fd=11))
0      0      192.168.0.223:56926   160.79.104.10:443  users:(("claude-desktop",pid=5831,fd=22))
0      0      192.168.0.223:41492   140.82.114.25:443  users:(("firefox-bin",pid=4076,fd=52))
0      0      192.168.0.223:48878  64.233.170.188:5228 users:(("chrome",pid=5068,fd=37))
`

func TestParseSSOutputRealFixture(t *testing.T) {
	conns := parseSSOutput(realSSFixture)
	if len(conns) != 4 {
		t.Fatalf("parseSSOutput() len = %d, want 4", len(conns))
	}

	want := Connection{Protocol: "tcp", LPort: "53404", RAddress: "160.79.104.10", RPort: "443", Program: "claude", PID: "6039", State: "ESTAB"}
	if conns[0] != want {
		t.Fatalf("parseSSOutput()[0] = %+v, want %+v", conns[0], want)
	}

	if conns[3].RPort != "5228" || conns[3].RAddress != "64.233.170.188" {
		t.Fatalf("parseSSOutput()[3] remote = %s:%s, want 64.233.170.188:5228", conns[3].RAddress, conns[3].RPort)
	}
}

func TestParseSSOutputIPv6(t *testing.T) {
	// Captured live from a real IPv6 loopback connection: ss brackets IPv6
	// addresses, unlike its IPv4 output. splitSSAddress's LastIndex(":")
	// split leaves the brackets in RAddress rather than stripping them —
	// this is only safe because monitor.remoteIP() strips brackets itself as
	// a fallback. This test exists to catch it if that ever stops being true.
	const line = "0      0      [::1]:56328 [::1]:12450 users:((\"nc\",pid=48399,fd=3))\n"

	conns := parseSSOutput(line)
	if len(conns) != 1 {
		t.Fatalf("parseSSOutput() len = %d, want 1", len(conns))
	}

	want := Connection{Protocol: "tcp", LPort: "56328", RAddress: "[::1]", RPort: "12450", Program: "nc", PID: "48399", State: "ESTAB"}
	if conns[0] != want {
		t.Fatalf("parseSSOutput()[0] = %+v, want %+v", conns[0], want)
	}
}

func TestParseSSOutputUnattributedProcess(t *testing.T) {
	// ss omits the whole process column when it can't attribute the socket
	// to a process (e.g. owned by another user without CAP_NET_ADMIN).
	const line = "0      0      192.168.0.223:53404   160.79.104.10:443\n"

	conns := parseSSOutput(line)
	if len(conns) != 1 {
		t.Fatalf("parseSSOutput() len = %d, want 1", len(conns))
	}

	if conns[0].Program != "" || conns[0].PID != "" {
		t.Fatalf("parseSSOutput()[0] = %+v, want empty Program/PID", conns[0])
	}

	if conns[0].RAddress != "160.79.104.10" || conns[0].RPort != "443" {
		t.Fatalf("parseSSOutput()[0] remote = %s:%s, want 160.79.104.10:443", conns[0].RAddress, conns[0].RPort)
	}
}

func TestParseSSOutputMultipleOwners(t *testing.T) {
	const line = `0      0      192.168.0.223:53404   160.79.104.10:443  users:(("nginx",pid=100,fd=5),("nginx",pid=100,fd=6))
`

	conns := parseSSOutput(line)
	if len(conns) != 1 {
		t.Fatalf("parseSSOutput() len = %d, want 1", len(conns))
	}

	if conns[0].Program != "nginx" || conns[0].PID != "100" {
		t.Fatalf("parseSSOutput()[0] = %+v, want Program=nginx PID=100", conns[0])
	}
}

func TestParseSSOutputSkipsMalformedLines(t *testing.T) {
	const output = `not even close to a valid line
0      0      192.168.0.223:53404   160.79.104.10:443  users:(("claude",pid=6039,fd=11))
192.168.0.223:missingport
`

	conns := parseSSOutput(output)
	if len(conns) != 1 {
		t.Fatalf("parseSSOutput() len = %d, want 1 (malformed lines skipped)", len(conns))
	}

	if conns[0].Program != "claude" {
		t.Fatalf("parseSSOutput()[0].Program = %q, want claude", conns[0].Program)
	}
}

func TestSSAvailable(t *testing.T) {
	installFakeSS(t, "#!/bin/sh\nexit 0\n")

	if !SSAvailable() {
		t.Fatal("SSAvailable() = false, want true with fake ss on PATH")
	}
}

func TestSSAvailableFalseWhenNotOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if SSAvailable() {
		t.Fatal("SSAvailable() = true, want false with empty PATH")
	}
}

func TestGetEstablishedConnectionsViaSS(t *testing.T) {
	installFakeSS(t, "#!/bin/sh\ncat <<'EOF'\n"+realSSFixture+"EOF\n")

	conns, err := GetEstablishedConnectionsViaSS()
	if err != nil {
		t.Fatalf("GetEstablishedConnectionsViaSS() error = %v", err)
	}

	if len(conns) != 4 {
		t.Fatalf("GetEstablishedConnectionsViaSS() len = %d, want 4", len(conns))
	}
}

func TestGetEstablishedConnectionsViaSSCommandFailure(t *testing.T) {
	installFakeSS(t, "#!/bin/sh\necho 'ss: permission denied' 1>&2\nexit 1\n")

	if _, err := GetEstablishedConnectionsViaSS(); err == nil {
		t.Fatal("GetEstablishedConnectionsViaSS() error = nil, want error when ss fails")
	}
}
