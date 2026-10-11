// Package service installs systemd units so hexwall, and the Zeek it reads, survive a reboot.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	unitDir     = "/etc/systemd/system"
	hexwallUnit = "hexwall.service"
	zeekUnit    = "zeek.service"
	// The first line of every unit hexwall writes. A zeek.service without it belongs to
	// someone else and is never overwritten.
	marker = "# Installed by hexwall install-service. Re-run it to update; edits here are overwritten."
	// hexwall's state directory; systemd creates it (StateDirectory=hexwall) and starts
	// hexwall there, so the default ./hexwall.db lands in it instead of in /.
	stateDir = "/var/lib/hexwall"
)

// Packaged Zeek units live here; one of them means Zeek already has a unit of its own.
var vendorUnitDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system"}

// Options describes the units to install.
type Options struct {
	Binary string   // absolute path of the hexwall binary the unit runs
	Args   []string // validated hexwall flags, already passed through WithSafeMode
	// Zeekctl is the zeekctl to run from zeek.service; empty when hexwall doesn't use Zeek.
	Zeekctl string
}

// Install writes the units, reloads systemd, enables them for boot, and (re)starts hexwall.
func Install(out io.Writer, opts Options) error {
	if os.Geteuid() != 0 {
		return errors.New("writing systemd units needs root (run with sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not found: install-service only supports systemd")
	}
	return install(out, opts, unitDir, vendorUnitDirs, runSystemctl)
}

func install(out io.Writer, opts Options, dir string, vendorDirs []string, systemctl func(args ...string) error) error {
	withZeek := false
	if opts.Zeekctl != "" {
		switch owned, err := zeekUnitOwner(dir, vendorDirs); {
		case err != nil:
			return err
		case owned:
			changed, err := writeUnit(filepath.Join(dir, zeekUnit), renderZeekUnit(opts.Zeekctl))
			if err != nil {
				return err
			}
			report(out, zeekUnit, dir, changed)
			withZeek = true
		default:
			_, _ = fmt.Fprintf(out, "✓ %s already exists and isn't hexwall's; left as is\n", zeekUnit)
			withZeek = true
		}
	}

	changed, err := writeUnit(filepath.Join(dir, hexwallUnit), renderHexwallUnit(opts.Binary, opts.Args, withZeek))
	if err != nil {
		return err
	}
	report(out, hexwallUnit, dir, changed)

	steps := [][]string{{"daemon-reload"}}
	if withZeek {
		steps = append(steps, []string{"enable", "--now", zeekUnit})
	}
	steps = append(steps, []string{"enable", hexwallUnit}, []string{"restart", hexwallUnit})
	for _, step := range steps {
		if err := systemctl(step...); err != nil {
			return fmt.Errorf("systemctl %s: %w", strings.Join(step, " "), err)
		}
	}

	_, _ = fmt.Fprintf(out, `
hexwall now starts at boot and restarts if it crashes.
  status:   systemctl status %[1]s
  logs:     journalctl -u %[1]s -f
  remove:   sudo systemctl disable --now %[1]s
`, hexwallUnit)
	return nil
}

// zeekUnitOwner reports whether zeek.service is free for hexwall to write: either absent,
// or a unit hexwall wrote earlier.
func zeekUnitOwner(dir string, vendorDirs []string) (bool, error) {
	for _, vendor := range vendorDirs {
		if _, err := os.Stat(filepath.Join(vendor, zeekUnit)); err == nil {
			return false, nil
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, zeekUnit))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return bytes.HasPrefix(data, []byte(marker)), nil
}

func writeUnit(path, content string) (changed bool, err error) {
	if current, err := os.ReadFile(path); err == nil && string(current) == content {
		return false, nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

func report(out io.Writer, unit, dir string, changed bool) {
	if changed {
		_, _ = fmt.Fprintf(out, "✓ wrote %s\n", filepath.Join(dir, unit))
	} else {
		_, _ = fmt.Fprintf(out, "✓ %s already up to date\n", filepath.Join(dir, unit))
	}
}

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func renderHexwallUnit(binary string, args []string, withZeek bool) string {
	after, wants := "network-online.target docker.service", "network-online.target"
	if withZeek {
		// Wants starts Zeek with hexwall; After makes hexwall wait for it, so ssl.log exists.
		after += " " + zeekUnit
		wants += " " + zeekUnit
	}
	execStart := make([]string, 0, len(args)+1)
	for _, arg := range append([]string{binary}, args...) {
		execStart = append(execStart, quoteExecArg(arg))
	}
	return marker + `
[Unit]
Description=hexwall outbound connection monitor
After=` + after + `
Wants=` + wants + `

[Service]
ExecStart=` + strings.Join(execStart, " ") + `
StateDirectory=hexwall
WorkingDirectory=` + stateDir + `
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

func renderZeekUnit(zeekctl string) string {
	zeekctl = quoteExecArg(zeekctl)
	// zeekctl starts Zeek in the background and exits, so the unit is a oneshot that stays
	// "active" until stopped.
	return marker + `
[Unit]
Description=Zeek network monitor (via zeekctl)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + zeekctl + ` deploy
ExecStop=` + zeekctl + ` stop

[Install]
WantedBy=multi-user.target
`
}

// quoteExecArg makes arg safe in an ExecStart= line, where systemd splits on whitespace,
// treats % as a specifier and expands $ as an environment variable.
func quoteExecArg(arg string) string {
	arg = strings.ReplaceAll(arg, "%", "%%")
	arg = strings.ReplaceAll(arg, "$", "$$")
	if arg != "" && !strings.ContainsAny(arg, " \t\"'\\") {
		return arg
	}
	arg = strings.ReplaceAll(arg, `\`, `\\`)
	arg = strings.ReplaceAll(arg, `"`, `\"`)
	return `"` + arg + `"`
}

// WithSafeMode returns the flags the unit runs hexwall with. A service starts at every
// boot, before anyone is watching, so it runs in watch mode unless the user asked for a
// mode explicitly.
func WithSafeMode(args []string) []string {
	for _, arg := range args {
		// Go's flag package accepts one or two dashes, with the value attached by = or not.
		if arg == "--mode" || arg == "-mode" || strings.HasPrefix(arg, "--mode=") || strings.HasPrefix(arg, "-mode=") {
			return args
		}
	}
	return append([]string{"--mode", "watch"}, args...)
}
