// Package enforcer terminates blocked connections, preferring to kill just the one
// connection over the whole owning process.
//
// KillConnection is the preferred entry point: it tries a precise, connection-level
// kill via `ss -K` (requires CONFIG_INET_DIAG_DESTROY and CAP_NET_ADMIN) and falls
// back to killing the whole process — KillProcess's behavior — when that isn't
// possible: ss is missing, the kernel doesn't support it, or hexwall isn't running
// with the needed capability. The process-level fallback remains coarser than
// intended: it takes down every other connection that process holds too.
package enforcer

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// protectedPrograms is the default set of programs that must never be killed.
// All keys MUST be lowercase: isProtected lowercases the input before lookup.
var protectedPrograms = map[string]bool{
	"systemd":          true,
	"init":             true,
	"sshd":             true,
	"networkmanager":   true,
	"systemd-resolved": true,
	"systemd-networkd": true,
	"dbus-daemon":      true,
	"containerd":       true,
	"dockerd":          true,
}

// SetProtectedPrograms replaces the default protected-program set.
// Keys are normalized to lowercase on entry because isProtected lowercases
// its input, so stored keys must match for the lookup to work.
func SetProtectedPrograms(programs map[string]bool) {
	normalized := make(map[string]bool, len(programs))
	for k, v := range programs {
		normalized[strings.ToLower(k)] = v
	}
	protectedPrograms = normalized
}

// isProtected reports whether the program name (case-insensitive) is in the protected set.
func isProtected(name string) bool {
	lower := strings.ToLower(name)
	return protectedPrograms[lower]
}

// checkGuardrails applies the safety checks shared by both kill paths below,
// before either one is attempted:
//   - Refuses any PID <= 0.
//   - Refuses PID 1 (init).
//   - Refuses hexwall's own PID.
//   - Refuses protected programs (case-insensitive match).
func checkGuardrails(pid int, program string) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d", pid)
	}

	if pid == 1 {
		return fmt.Errorf("refusing to signal init (PID 1)")
	}

	if pid == os.Getpid() {
		return fmt.Errorf("refusing to signal own process (PID %d)", pid)
	}

	if isProtected(program) {
		return fmt.Errorf("refusing to kill protected program %q (PID %d)", program, pid)
	}

	return nil
}

// KillProcess terminates the process holding a connection.
//
// Guardrails: see checkGuardrails.
// Sends SIGTERM first, waits a grace period, then SIGKILL if still alive.
// The actual signal-sending is platform-specific; see terminate in
// enforcer_unix.go / enforcer_windows.go.
func KillProcess(pid int, program string, remoteAddr string) error {
	if err := checkGuardrails(pid, program); err != nil {
		return err
	}

	slog.Warn("killing connection", "pid", pid, "program", program, "address", remoteAddr)

	return terminate(pid, program)
}

// KillConnection kills the single connection identified by localPort/remoteIP/remotePort,
// owned by pid/program. It prefers a precise, connection-level kill (see killSocket in
// enforcer_socket.go) that leaves every other connection the process holds untouched,
// falling back to killing the whole process only when that isn't possible.
//
// Guardrails are the same as KillProcess's, checked once before either kill path
// is attempted.
func KillConnection(pid int, program, localPort, remoteIP, remotePort string) error {
	if err := checkGuardrails(pid, program); err != nil {
		return err
	}

	remoteAddr := remoteIP + ":" + remotePort

	socketErr := killSocket(localPort, remoteIP, remotePort)
	if socketErr == nil {
		slog.Info("killed single connection", "pid", pid, "program", program, "local_port", localPort, "remote", remoteAddr)
		return nil
	}
	slog.Debug("connection-level kill unavailable, falling back to killing the process", "err", socketErr, "pid", pid, "program", program)

	slog.Warn("killing connection", "pid", pid, "program", program, "address", remoteAddr)

	return terminate(pid, program)
}

// ParsePID converts a string PID to int, returning an error for invalid input.
func ParsePID(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, fmt.Errorf("empty or dash PID %q", s)
	}

	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid PID %q: %w", s, err)
	}

	return pid, nil
}
