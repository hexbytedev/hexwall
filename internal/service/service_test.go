package service

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWithSafeMode(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"no flags", nil, []string{"--mode", "watch"}},
		{"other flags only", []string{"--debug"}, []string{"--mode", "watch", "--debug"}},
		{"explicit enforce", []string{"--mode", "enforce"}, []string{"--mode", "enforce"}},
		{"equals form", []string{"--mode=enforce", "--debug"}, []string{"--mode=enforce", "--debug"}},
		{"single dash", []string{"-mode", "enforce"}, []string{"-mode", "enforce"}},
		{"single dash equals", []string{"-mode=watch"}, []string{"-mode=watch"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithSafeMode(tt.args); !slices.Equal(got, tt.want) {
				t.Fatalf("WithSafeMode(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestQuoteExecArg(t *testing.T) {
	tests := map[string]string{
		"/usr/local/bin/hexwall": "/usr/local/bin/hexwall",
		"/path with space/x":     `"/path with space/x"`,
		"100%":                   "100%%",
		"$HOME":                  "$$HOME",
		`a"b`:                    `"a\"b"`,
		"":                       `""`,
	}
	for in, want := range tests {
		if got := quoteExecArg(in); got != want {
			t.Errorf("quoteExecArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderHexwallUnit(t *testing.T) {
	unit := renderHexwallUnit("/usr/local/bin/hexwall", []string{"--mode", "watch", "--zeek-log", "/opt/zeek/logs/current/ssl.log"}, true)
	for _, want := range []string{
		marker + "\n",
		"ExecStart=/usr/local/bin/hexwall --mode watch --zeek-log /opt/zeek/logs/current/ssl.log\n",
		"After=network-online.target docker.service zeek.service\n",
		"Wants=network-online.target zeek.service\n",
		"WorkingDirectory=/var/lib/hexwall\n",
		"Restart=on-failure\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit is missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(renderHexwallUnit("/x", nil, false), "zeek") {
		t.Error("unit without Zeek still references zeek.service")
	}
}

type fakeSystemctl struct{ calls []string }

func (f *fakeSystemctl) run(args ...string) error {
	f.calls = append(f.calls, strings.Join(args, " "))
	return nil
}

func TestInstall_WritesUnitsAndStartsHexwall(t *testing.T) {
	dir := t.TempDir()
	systemctl := &fakeSystemctl{}
	opts := Options{Binary: "/usr/local/bin/hexwall", Args: []string{"--mode", "watch"}, Zeekctl: "/opt/zeek/bin/zeekctl"}

	var out bytes.Buffer
	if err := install(&out, opts, dir, nil, systemctl.run); err != nil {
		t.Fatalf("install() error = %v", err)
	}

	for _, unit := range []string{hexwallUnit, zeekUnit} {
		if _, err := os.Stat(filepath.Join(dir, unit)); err != nil {
			t.Errorf("%s not written: %v", unit, err)
		}
	}
	want := []string{"daemon-reload", "enable --now zeek.service", "enable hexwall.service", "restart hexwall.service"}
	if !slices.Equal(systemctl.calls, want) {
		t.Fatalf("systemctl calls = %q, want %q", systemctl.calls, want)
	}
}

// A zeek.service someone else wrote (a distro package, or by hand) must survive untouched.
func TestInstall_KeepsForeignZeekUnit(t *testing.T) {
	dir := t.TempDir()
	foreign := "[Service]\nExecStart=/usr/bin/zeek -i eth1\n"
	if err := os.WriteFile(filepath.Join(dir, zeekUnit), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := Options{Binary: "/x", Zeekctl: "/opt/zeek/bin/zeekctl"}
	if err := install(&bytes.Buffer{}, opts, dir, nil, (&fakeSystemctl{}).run); err != nil {
		t.Fatalf("install() error = %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(dir, zeekUnit))
	if string(got) != foreign {
		t.Fatalf("foreign zeek.service was overwritten:\n%s", got)
	}
	hexwall, _ := os.ReadFile(filepath.Join(dir, hexwallUnit))
	if !strings.Contains(string(hexwall), "After=network-online.target docker.service zeek.service") {
		t.Fatalf("hexwall.service doesn't order itself after the existing zeek.service:\n%s", hexwall)
	}
}

func TestInstall_WithoutZeek(t *testing.T) {
	dir := t.TempDir()
	systemctl := &fakeSystemctl{}
	if err := install(&bytes.Buffer{}, Options{Binary: "/x"}, dir, nil, systemctl.run); err != nil {
		t.Fatalf("install() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, zeekUnit)); !os.IsNotExist(err) {
		t.Fatalf("zeek.service written although hexwall doesn't use Zeek (err %v)", err)
	}
	if slices.Contains(systemctl.calls, "enable --now zeek.service") {
		t.Fatalf("zeek.service enabled although hexwall doesn't use Zeek: %q", systemctl.calls)
	}
}

func TestUninstall_RemovesOnlyHexwallsUnits(t *testing.T) {
	dir := t.TempDir()
	if err := install(&bytes.Buffer{}, Options{Binary: "/x"}, dir, nil, (&fakeSystemctl{}).run); err != nil {
		t.Fatal(err)
	}
	foreign := "[Service]\nExecStart=/usr/bin/zeek -i eth1\n"
	if err := os.WriteFile(filepath.Join(dir, zeekUnit), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}

	systemctl := &fakeSystemctl{}
	if err := uninstall(&bytes.Buffer{}, dir, systemctl.run); err != nil {
		t.Fatalf("uninstall() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, hexwallUnit)); !os.IsNotExist(err) {
		t.Fatalf("hexwall.service still there (err %v)", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, zeekUnit)); string(got) != foreign {
		t.Fatalf("foreign zeek.service changed:\n%s", got)
	}
	want := []string{"disable --now hexwall.service", "daemon-reload"}
	if !slices.Equal(systemctl.calls, want) {
		t.Fatalf("systemctl calls = %q, want %q", systemctl.calls, want)
	}
}

func TestUninstall_NothingInstalled(t *testing.T) {
	systemctl := &fakeSystemctl{}
	if err := uninstall(&bytes.Buffer{}, t.TempDir(), systemctl.run); err != nil {
		t.Fatalf("uninstall() error = %v", err)
	}
	if len(systemctl.calls) != 0 {
		t.Fatalf("systemctl called with nothing installed: %q", systemctl.calls)
	}
}
