package enforcer

import (
	"fmt"
	"os/exec"
	"strings"
)

// killSocket attempts to close exactly one TCP connection — identified by its
// local port and the remote IP:port it is talking to — via `ss -K`, which asks
// the kernel to destroy that single socket (CONFIG_INET_DIAG_DESTROY) without
// touching any other connection the owning process holds.
//
// ss -K's own exit code is not a reliable success signal: it has been observed
// to exit 0 even when the kernel refused the destroy request for lack of
// CAP_NET_ADMIN. So after running it, the socket table is re-queried for this
// exact tuple; if it is still there, the kill is treated as failed regardless
// of what ss itself reported.
//
// This needs no build tag: ss is a Linux-only tool (iproute2), but on any
// platform or environment where it is missing, unsupported, or unprivileged,
// this simply returns an error, and the caller falls back to killing the
// whole process.
func killSocket(localPort, remoteIP, remotePort string) error {
	// Best-effort: its exit code is not trusted. The recheck below is the
	// actual source of truth.
	_ = exec.Command("ss", "-K", "dst", remoteIP, "dport", remotePort, "sport", localPort).Run()

	stillEstablished, err := socketStillEstablished(localPort, remoteIP, remotePort)
	if err != nil {
		return fmt.Errorf("could not verify socket state after ss -K: %w", err)
	}
	if stillEstablished {
		return fmt.Errorf("ss -K did not close the connection (missing CAP_NET_ADMIN, unsupported kernel, or ss unavailable)")
	}

	return nil
}

// socketStillEstablished reports whether a TCP connection matching this exact
// local-port/remote-IP/remote-port tuple is still in the ESTABLISHED state.
func socketStillEstablished(localPort, remoteIP, remotePort string) (bool, error) {
	filter := fmt.Sprintf("( sport = :%s and dst %s and dport = %s )", localPort, remoteIP, remotePort)

	out, err := exec.Command("ss", "-tn", "state", "established", filter).Output()
	if err != nil {
		return false, fmt.Errorf("ss state query failed: %w", err)
	}

	dataLines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) != "" {
			dataLines++
		}
	}

	// The first line is always the column header; anything past that is a match.
	return dataLines > 1, nil
}
