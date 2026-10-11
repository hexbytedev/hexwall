package zeek

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInstallScript_WritesThenSkipsIdentical(t *testing.T) {
	siteDir := t.TempDir()

	changed, err := installScript(siteDir, DNSBypassScript)
	if err != nil || !changed {
		t.Fatalf("first installScript() = %v, %v; want true, nil", changed, err)
	}
	got, err := os.ReadFile(filepath.Join(siteDir, scriptName))
	if err != nil || string(got) != string(DNSBypassScript) {
		t.Fatalf("installed script differs from the embedded one (err %v)", err)
	}

	changed, err = installScript(siteDir, DNSBypassScript)
	if err != nil || changed {
		t.Fatalf("second installScript() = %v, %v; want false, nil", changed, err)
	}
}

// An older copy (e.g. one without $sub) must be replaced, or hexwall can't read its notices.
func TestInstallScript_ReplacesOutdatedCopy(t *testing.T) {
	siteDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(siteDir, scriptName), []byte("# old version\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := installScript(siteDir, DNSBypassScript)
	if err != nil || !changed {
		t.Fatalf("installScript() = %v, %v; want true, nil", changed, err)
	}
}

func TestEnsureLoaded_AppendsOnce(t *testing.T) {
	localZeek := filepath.Join(t.TempDir(), "local.zeek")
	original := "@load misc/detect-traceroute\n@load tuning/defaults" // no trailing newline
	if err := os.WriteFile(localZeek, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	for i, want := range []bool{true, false} {
		added, err := ensureLoaded(localZeek)
		if err != nil || added != want {
			t.Fatalf("ensureLoaded() call %d = %v, %v; want %v, nil", i+1, added, err, want)
		}
	}

	data, _ := os.ReadFile(localZeek)
	lines := strings.Split(string(data), "\n")
	if !slices.Contains(lines, "@load tuning/defaults") {
		t.Fatalf("last existing line was mangled:\n%s", data)
	}
	if strings.Count(string(data), loadLine) != 1 {
		t.Fatalf("want exactly one %q line:\n%s", loadLine, data)
	}
}

func TestMissingInterfaces(t *testing.T) {
	nodeCfg := filepath.Join(t.TempDir(), "node.cfg")
	// Shape of zeekctl's default standalone node.cfg, plus a worker using a packet-source prefix.
	content := `# Example ZeekControl node configuration.
[zeek]
type=standalone
host=localhost
interface=eth0

[worker-1]
type=worker
interface=af_packet::wlx001ea6c37e44
#interface=commented0
`
	if err := os.WriteFile(nodeCfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	exists := func(name string) bool { return name == "wlx001ea6c37e44" }
	missing, err := missingInterfaces(nodeCfg, exists)
	if err != nil {
		t.Fatalf("missingInterfaces() error = %v", err)
	}
	if !slices.Equal(missing, []string{"eth0"}) {
		t.Fatalf("missingInterfaces() = %v, want [eth0]", missing)
	}
}

func TestZeekLogDir(t *testing.T) {
	prefix := t.TempDir()
	if got, want := zeekLogDir(prefix), filepath.Join(prefix, "logs"); got != want {
		t.Fatalf("zeekLogDir() without zeekctl.cfg = %q, want %q", got, want)
	}

	if err := os.MkdirAll(filepath.Join(prefix, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "# Log rotation\nLogRotationInterval = 3600\nLogDir = /var/log/zeek\n"
	if err := os.WriteFile(filepath.Join(prefix, "etc", "zeekctl.cfg"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := zeekLogDir(prefix); got != "/var/log/zeek" {
		t.Fatalf("zeekLogDir() = %q, want %q", got, "/var/log/zeek")
	}
}
