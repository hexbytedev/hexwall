//go:build windows

package enforcer

import "fmt"

// terminate is unimplemented on Windows: the SIGTERM-then-SIGKILL grace
// period this package relies on is a POSIX signal semantic that Windows does
// not have. hexwall does not publish Windows binaries; this stub exists so
// the module vets and builds cleanly cross-platform.
func terminate(pid int, program string) error {
	return fmt.Errorf("killing processes is not supported on windows (pid %d, program %q)", pid, program)
}
