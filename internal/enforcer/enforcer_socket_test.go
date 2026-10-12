package enforcer

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// installFakeSS writes an executable shell script named "ss" into a temp
// directory and prepends it to PATH, mirroring the same trick used for somo
// and docker elsewhere in this project.
func installFakeSS(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()

	path := filepath.Join(dir, "ss")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ss: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// ---- killSocket, via a fake ss on PATH ----------------------------------

func TestKillSocketSucceedsWhenConnectionGoneAfterward(t *testing.T) {
	installFakeSS(t, "#!/bin/sh\n"+
		"case \"$1\" in\n"+
		"  -K) exit 0 ;;\n"+
		"  -tn) echo \"Recv-Q Send-Q Local Address:Port  Peer Address:Port\" ;;\n"+ // header only: gone
		"esac\n")

	if err := killSocket("51820", "203.0.113.10", "443"); err != nil {
		t.Fatalf("killSocket() error = %v, want nil when the recheck shows the socket gone", err)
	}
}

func TestKillSocketFailsWhenConnectionStillThere(t *testing.T) {
	installFakeSS(t, "#!/bin/sh\n"+
		"case \"$1\" in\n"+
		"  -K) exit 0 ;;\n"+ // ss -K can exit 0 even when it changed nothing (e.g. EPERM)
		"  -tn) printf \"Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n0 0 10.0.0.5:51820 203.0.113.10:443\\n\" ;;\n"+
		"esac\n")

	err := killSocket("51820", "203.0.113.10", "443")
	if err == nil {
		t.Fatal("killSocket() error = nil, want error when the recheck still shows the connection")
	}

	if !strings.Contains(err.Error(), "did not close") {
		t.Fatalf("killSocket() error = %q, want it to mention the connection was not closed", err)
	}
}

func TestKillSocketFailsWhenSSUnavailable(t *testing.T) {
	// Empty PATH: exec.Command("ss", ...) can't find the binary at all,
	// simulating a platform (e.g. macOS) where ss doesn't exist.
	t.Setenv("PATH", t.TempDir())

	err := killSocket("51820", "203.0.113.10", "443")
	if err == nil {
		t.Fatal("killSocket() error = nil, want error when ss is not on PATH")
	}
}

// ---- socketStillEstablished, against a real loopback connection ---------

func requireSS(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss not available in this environment")
	}
}

// openLoopbackConnection sets up a real, live TCP connection over loopback
// and returns the client side plus its own and the server's port, so
// socketStillEstablished can be checked against a socket that genuinely
// exists rather than a fabricated tuple.
func openLoopbackConnection(t *testing.T) (client net.Conn, clientPort, serverPort string) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)

	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	server := <-accepted

	t.Cleanup(func() { _ = server.Close() })

	local := conn.LocalAddr().(*net.TCPAddr)
	remote := conn.RemoteAddr().(*net.TCPAddr)

	return conn, strconv.Itoa(local.Port), strconv.Itoa(remote.Port)
}

func TestSocketStillEstablishedTrueForLiveConnection(t *testing.T) {
	requireSS(t)

	_, clientPort, serverPort := openLoopbackConnection(t)

	still, err := socketStillEstablished(clientPort, "127.0.0.1", serverPort)
	if err != nil {
		t.Fatalf("socketStillEstablished() error = %v", err)
	}

	if !still {
		t.Fatal("socketStillEstablished() = false, want true for a live connection")
	}
}

func TestSocketStillEstablishedFalseAfterClose(t *testing.T) {
	requireSS(t)

	conn, clientPort, serverPort := openLoopbackConnection(t)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Closing the local side takes the socket out of ESTABLISHED essentially
	// immediately, but allow a couple of short retries to avoid flakiness.
	var (
		still bool
		err   error
	)
	for i := 0; i < 10; i++ {
		still, err = socketStillEstablished(clientPort, "127.0.0.1", serverPort)
		if err != nil {
			t.Fatalf("socketStillEstablished() error = %v", err)
		}

		if !still {
			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if still {
		t.Fatal("socketStillEstablished() = true, want false after the connection was closed")
	}
}

func TestSocketStillEstablishedNoMatch(t *testing.T) {
	requireSS(t)

	still, err := socketStillEstablished("1", "203.0.113.99", "1")
	if err != nil {
		t.Fatalf("socketStillEstablished() error = %v", err)
	}

	if still {
		t.Fatal("socketStillEstablished() = true, want false for a tuple that was never connected")
	}
}

// ---- KillConnection: guardrails, then ss -K, then the process fallback ----

// noSuchPID is above the kernel's pid_max (at most 2^22), so no process can have it: if a
// test ever reaches the process fallback, the signal fails with ESRCH instead of hitting
// a real process.
const noSuchPID = 1 << 30

// installRecordingSS installs a fake ss that appends each invocation to a log file and
// answers the recheck with stillThere's connection or with the header alone.
func installRecordingSS(t *testing.T, stillThere bool) (callLog string) {
	t.Helper()
	callLog = filepath.Join(t.TempDir(), "ss-calls")

	answer := `echo "Recv-Q Send-Q Local Address:Port  Peer Address:Port"`
	if stillThere {
		answer = `printf "Recv-Q Send-Q Local Address:Port  Peer Address:Port\n0 0 10.0.0.5:51820 203.0.113.10:443\n"`
	}

	installFakeSS(t, "#!/bin/sh\n"+
		"echo \"$@\" >> '"+callLog+"'\n"+
		"case \"$1\" in\n"+
		"  -K) exit 0 ;;\n"+
		"  -tn) "+answer+" ;;\n"+
		"esac\n")

	return callLog
}

func TestKillConnectionClosesJustTheSocket(t *testing.T) {
	callLog := installRecordingSS(t, false)

	if err := KillConnection(noSuchPID, "curl", "51820", "203.0.113.10", "443"); err != nil {
		t.Fatalf("KillConnection() error = %v, want nil: ss -K closed the socket, so no process signal was needed", err)
	}

	calls, _ := os.ReadFile(callLog)
	if !strings.Contains(string(calls), "-K dst 203.0.113.10 dport 443 sport 51820") {
		t.Fatalf("ss calls = %q, want an ss -K for exactly this connection", calls)
	}
}

// When ss -K can't close the socket, KillConnection falls back to signalling the process.
// noSuchPID makes that signal fail harmlessly; the error proves the fallback ran and is
// a failure, not a guardrail refusal.
func TestKillConnectionFallsBackToProcessKill(t *testing.T) {
	installRecordingSS(t, true)

	err := KillConnection(noSuchPID, "curl", "51820", "203.0.113.10", "443")
	if err == nil || !strings.Contains(err.Error(), "SIGTERM") {
		t.Fatalf("KillConnection() error = %v, want the SIGTERM fallback's error", err)
	}

	if errors.Is(err, ErrRefused) {
		t.Fatalf("KillConnection() error = %v is ErrRefused, want a plain failure", err)
	}
}

// Guardrails run before anything else: a refused kill never even calls ss.
func TestKillConnectionRefusedBeforeTouchingSS(t *testing.T) {
	callLog := installRecordingSS(t, false)

	if err := KillConnection(1, "curl", "51820", "203.0.113.10", "443"); !errors.Is(err, ErrRefused) {
		t.Fatalf("KillConnection(PID 1) error = %v, want ErrRefused", err)
	}

	if _, err := os.Stat(callLog); !os.IsNotExist(err) {
		t.Fatal("ss was called for a refused kill; guardrails must run first")
	}
}
