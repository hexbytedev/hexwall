package zeek

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	scriptName = "dns-bypass.zeek"
	loadLine   = "@load dns-bypass"
	// Where Zeek's binary packages install; under sudo, /opt/zeek/bin is usually not on PATH.
	defaultZeekConfig = "/opt/zeek/bin/zeek-config"
)

// Setup installs DNSBypassScript into a local Zeek, loads it from local.zeek, and checks
// that the interfaces Zeek is told to watch exist. It prints what it did, what is still
// wrong, and the hexwall flags that read the resulting logs. It does not restart Zeek.
func Setup(out io.Writer) error {
	zeekConfig, err := findZeekConfig()
	if err != nil {
		return err
	}
	siteDir, err := zeekConfigValue(zeekConfig, "--site_dir")
	if err != nil {
		return err
	}
	prefix, err := zeekConfigValue(zeekConfig, "--prefix")
	if err != nil {
		return err
	}

	changed, err := installScript(siteDir, DNSBypassScript)
	if err != nil {
		return err
	}
	if changed {
		_, _ = fmt.Fprintf(out, "✓ installed %s\n", filepath.Join(siteDir, scriptName))
	} else {
		_, _ = fmt.Fprintf(out, "✓ %s already up to date\n", filepath.Join(siteDir, scriptName))
	}

	localZeek := filepath.Join(siteDir, "local.zeek")
	added, err := ensureLoaded(localZeek)
	if err != nil {
		return err
	}
	if added {
		_, _ = fmt.Fprintf(out, "✓ added %q to %s\n", loadLine, localZeek)
	} else {
		_, _ = fmt.Fprintf(out, "✓ %s already loads the script\n", localZeek)
	}

	nodeCfg := filepath.Join(prefix, "etc", "node.cfg")
	missing, err := missingInterfaces(nodeCfg, interfaceExists)
	if err != nil {
		_, _ = fmt.Fprintf(out, "! could not check %s: %v\n", nodeCfg, err)
	}
	for _, name := range missing {
		_, _ = fmt.Fprintf(out, "✗ %s tells Zeek to watch %q, which does not exist on this machine (available: %s)\n",
			nodeCfg, name, strings.Join(interfaceNames(), ", "))
	}

	logDir := zeekLogDir(prefix)
	_, _ = fmt.Fprintf(out, `
Next steps:
  1. sudo %s deploy          (restarts Zeek with the script loaded)
  2. run hexwall with:
       --zeek-log %s --enable-zeek --zeek-notice-log %s
`,
		filepath.Join(prefix, "bin", "zeekctl"),
		filepath.Join(logDir, "current", "ssl.log"),
		filepath.Join(logDir, "current", "notice.log"))

	if len(missing) > 0 {
		return fmt.Errorf("fix the interface in %s before deploying: Zeek cannot start on an interface that does not exist", nodeCfg)
	}
	return nil
}

// Zeekctl returns the path of the local Zeek's zeekctl, located through zeek-config.
func Zeekctl() (string, error) {
	zeekConfig, err := findZeekConfig()
	if err != nil {
		return "", err
	}
	prefix, err := zeekConfigValue(zeekConfig, "--prefix")
	if err != nil {
		return "", err
	}
	return filepath.Join(prefix, "bin", "zeekctl"), nil
}

func findZeekConfig() (string, error) {
	if path, err := exec.LookPath("zeek-config"); err == nil {
		return path, nil
	}
	if _, err := os.Stat(defaultZeekConfig); err == nil {
		return defaultZeekConfig, nil
	}
	return "", errors.New("zeek-config not found on PATH or at " + defaultZeekConfig + "; is Zeek installed?")
}

func zeekConfigValue(zeekConfig, flag string) (string, error) {
	out, err := exec.Command(zeekConfig, flag).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", zeekConfig, flag, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// installScript writes script into siteDir unless an identical copy is already there.
func installScript(siteDir string, script []byte) (changed bool, err error) {
	path := filepath.Join(siteDir, scriptName)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, script) {
		return false, nil
	}
	if err := os.WriteFile(path, script, 0o644); err != nil {
		return false, permissionHint(fmt.Errorf("write %s: %w", path, err))
	}
	return true, nil
}

// ensureLoaded appends the @load line to local.zeek unless it is already there.
func ensureLoaded(localZeek string) (added bool, err error) {
	data, err := os.ReadFile(localZeek)
	if err != nil {
		return false, permissionHint(fmt.Errorf("read %s: %w", localZeek, err))
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == loadLine {
			return false, nil
		}
	}

	addition := "\n# Added by hexwall zeek-setup: DNS-bypass notices that hexwall reads.\n" + loadLine + "\n"
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		addition = "\n" + addition
	}
	file, err := os.OpenFile(localZeek, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return false, permissionHint(fmt.Errorf("open %s: %w", localZeek, err))
	}
	if _, err := file.WriteString(addition); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("append to %s: %w", localZeek, err)
	}
	return true, file.Close()
}

// missingInterfaces returns the interfaces named in node.cfg that exists reports as absent.
// Newer zeekctl accepts a packet-source prefix ("af_packet::eth0"); only the name is checked.
func missingInterfaces(nodeCfg string, exists func(string) bool) ([]string, error) {
	file, err := os.Open(nodeCfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var missing []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || strings.TrimSpace(key) != "interface" {
			continue
		}
		name := strings.TrimSpace(value)
		if i := strings.LastIndex(name, "::"); i >= 0 {
			name = name[i+2:]
		}
		if name != "" && !exists(name) {
			missing = append(missing, name)
		}
	}
	return missing, scanner.Err()
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func interfaceNames() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names
}

// zeekLogDir reads LogDir from zeekctl.cfg, falling back to zeekctl's default.
func zeekLogDir(prefix string) string {
	if data, err := os.ReadFile(filepath.Join(prefix, "etc", "zeekctl.cfg")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "LogDir") {
				return strings.TrimSpace(value)
			}
		}
	}
	return filepath.Join(prefix, "logs")
}

func permissionHint(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w (run with sudo)", err)
	}
	return err
}
