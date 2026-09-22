//go:build windows

package enforcer

import "fmt"

// terminate is unimplemented on Windows: the SIGTERM-then-SIGKILL grace
// period this package relies on is a POSIX signal semantic that Windows does
// not have. hexwall does not support Windows — CI no longer builds or tests
// this file, so treat it as an unmaintained stub, not a courtesy compile target.
func terminate(pid int, program string) error {
	return fmt.Errorf("killing processes is not supported on windows (pid %d, program %q)", pid, program)
}
