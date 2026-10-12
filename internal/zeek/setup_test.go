package zeek

import (
	"bytes"
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

// Setup then Teardown must give local.zeek back exactly as it was.
func TestRemoveLoad_UndoesEnsureLoaded(t *testing.T) {
	localZeek := filepath.Join(t.TempDir(), "local.zeek")
	original := "@load misc/detect-traceroute\n\n@load tuning/defaults\n"
	if err := os.WriteFile(localZeek, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ensureLoaded(localZeek); err != nil {
		t.Fatal(err)
	}
	removed, err := removeLoad(localZeek)
	if err != nil || !removed {
		t.Fatalf("removeLoad() = %v, %v; want true, nil", removed, err)
	}
	got, _ := os.ReadFile(localZeek)
	if string(got) != original {
		t.Fatalf("local.zeek after setup+teardown:\n%q\nwant:\n%q", got, original)
	}

	if removed, err := removeLoad(localZeek); err != nil || removed {
		t.Fatalf("second removeLoad() = %v, %v; want false, nil", removed, err)
	}
}

func TestRemoveScript_OnlyDeletesHexwallsOwn(t *testing.T) {
	dir := t.TempDir()

	ours := filepath.Join(dir, "ours.zeek")
	if err := os.WriteFile(ours, DNSBypassScript, 0o644); err != nil {
		t.Fatal(err)
	}
	if deleted, err := removeScript(ours); err != nil || !deleted {
		t.Fatalf("removeScript(hexwall's script) = %v, %v; want true, nil", deleted, err)
	}

	foreign := filepath.Join(dir, "foreign.zeek")
	if err := os.WriteFile(foreign, []byte("# someone's own dns-bypass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if deleted, err := removeScript(foreign); err != nil || deleted {
		t.Fatalf("removeScript(foreign) = %v, %v; want false, nil", deleted, err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign script was deleted: %v", err)
	}

	if deleted, err := removeScript(filepath.Join(dir, "missing.zeek")); err != nil || deleted {
		t.Fatalf("removeScript(missing) = %v, %v; want false, nil", deleted, err)
	}
}

// fakeZeek builds a Zeek install in a temp dir (site dir with a local.zeek, node.cfg
// watching iface, zeekctl.cfg) and a fake zeek-config on PATH that points at it.
func fakeZeek(t *testing.T, iface string) (siteDir, prefix string) {
	t.Helper()
	prefix = t.TempDir()
	siteDir = filepath.Join(prefix, "share", "zeek", "site")
	for _, dir := range []string{siteDir, filepath.Join(prefix, "etc"), filepath.Join(prefix, "bin")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(siteDir, "local.zeek"):        "@load misc/detect-traceroute\n",
		filepath.Join(prefix, "etc", "node.cfg"):    "[zeek]\ntype=standalone\ninterface=" + iface + "\n",
		filepath.Join(prefix, "etc", "zeekctl.cfg"): "LogDir = " + filepath.Join(prefix, "logs") + "\n",
		filepath.Join(prefix, "bin", "zeek-config"): "#!/bin/sh\ncase \"$1\" in\n  --site_dir) echo '" + siteDir + "' ;;\n  --prefix) echo '" + prefix + "' ;;\nesac\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(prefix, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	return siteDir, prefix
}

func anyInterface(t *testing.T) string {
	t.Helper()
	names := interfaceNames()
	if len(names) == 0 {
		t.Skip("no network interfaces")
	}
	return names[0]
}

// The whole user journey: zeek-setup installs and loads the script and prints the right
// hexwall flags; uninstall's Teardown gives local.zeek back exactly as it was.
func TestSetupThenTeardown(t *testing.T) {
	siteDir, prefix := fakeZeek(t, anyInterface(t))
	original, _ := os.ReadFile(filepath.Join(siteDir, "local.zeek"))

	var out bytes.Buffer
	if err := Setup(&out); err != nil {
		t.Fatalf("Setup() error = %v\n%s", err, out.String())
	}
	if installed, err := os.ReadFile(filepath.Join(siteDir, scriptName)); err != nil || !bytes.Equal(installed, DNSBypassScript) {
		t.Fatalf("script not installed (err %v)", err)
	}
	for _, want := range []string{
		filepath.Join(prefix, "bin", "zeekctl") + " deploy",
		"--zeek-log " + filepath.Join(prefix, "logs", "current", "ssl.log"),
		"--zeek-notice-log " + filepath.Join(prefix, "logs", "current", "notice.log"),
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("Setup() output is missing %q:\n%s", want, out.String())
		}
	}

	if err := Teardown(&bytes.Buffer{}); err != nil {
		t.Fatalf("Teardown() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(siteDir, scriptName)); !os.IsNotExist(err) {
		t.Fatalf("script still installed after Teardown (err %v)", err)
	}
	if after, _ := os.ReadFile(filepath.Join(siteDir, "local.zeek")); !bytes.Equal(after, original) {
		t.Fatalf("local.zeek after Setup+Teardown:\n%q\nwant:\n%q", after, original)
	}
}

// Zeek can't start on an interface that doesn't exist; Setup must say so and fail.
func TestSetupReportsMissingInterface(t *testing.T) {
	fakeZeek(t, "hexwall-test-no-such-if0")

	var out bytes.Buffer
	err := Setup(&out)
	if err == nil {
		t.Fatalf("Setup() error = nil, want an error for a missing interface\n%s", out.String())
	}
	if !strings.Contains(out.String(), `"hexwall-test-no-such-if0", which does not exist`) {
		t.Fatalf("Setup() output doesn't name the missing interface:\n%s", out.String())
	}
}

func TestZeekctlFromZeekConfig(t *testing.T) {
	_, prefix := fakeZeek(t, anyInterface(t))
	got, err := Zeekctl()
	if err != nil || got != filepath.Join(prefix, "bin", "zeekctl") {
		t.Fatalf("Zeekctl() = %q, %v; want %q", got, err, filepath.Join(prefix, "bin", "zeekctl"))
	}
}
