//go:build !windows

package enforcer

import (
	"fmt"
	"log/slog"
	"syscall"
	"time"
)

// terminate sends SIGTERM, waits a grace period, then escalates to SIGKILL
// if the process is still alive.
func terminate(pid int, program string) error {
	// SIGTERM first — allows graceful shutdown.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to PID %d: %w", pid, err)
	}

	// Grace period: wait up to 2 seconds for the process to exit.
	time.Sleep(2 * time.Second)

	// Check whether the process still exists.
	if err := syscall.Kill(pid, 0); err != nil {
		// Process is gone — SIGTERM worked.
		slog.Info("process terminated by SIGTERM", "pid", pid, "program", program)
		return nil
	}

	// Process still alive — escalate to SIGKILL.
	slog.Warn("process survived SIGTERM, sending SIGKILL", "pid", pid, "program", program)

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("send SIGKILL to PID %d: %w", pid, err)
	}

	return nil
}
