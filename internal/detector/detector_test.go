package detector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeDocker writes an executable shell script named "docker" into a
// temp directory and prepends it to PATH, mirroring the same trick used for
// somo elsewhere in this project (see internal/connlist/connlist_test.go).
func installFakeDocker(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeRegularFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fake db"), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

// failDockerFallback returns a fallback that fails the test if it is ever
// called, for asserting the physical-path branch short-circuits correctly.
func failDockerFallback(t *testing.T) func() (string, error) {
	t.Helper()
	return func() (string, error) {
		t.Fatal("docker fallback should not have been called")
		return "", nil
	}
}

// ---- validateDBFile --------------------------------------------------

func TestValidateDBFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	regular := filepath.Join(dir, "pihole-FTL.db")
	writeRegularFile(t, regular)

	if err := validateDBFile(regular); err != nil {
		t.Fatalf("validateDBFile(regular file) error = %v, want nil", err)
	}

	if err := validateDBFile(dir); err == nil {
		t.Fatal("validateDBFile(directory) error = nil, want error")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("validateDBFile(directory) error = %q, want it to mention 'not a regular file'", err)
	}

	missing := filepath.Join(dir, "nope.db")
	if err := validateDBFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validateDBFile(missing) error = %v, want os.ErrNotExist", err)
	}
}

// ---- findDBPath (physical vs. Docker fallback) -------------------------

func TestFindDBPathPhysicalFound(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	physical := filepath.Join(dir, "pihole-FTL.db")
	writeRegularFile(t, physical)

	got, err := findDBPath(physical, failDockerFallback(t))
	if err != nil {
		t.Fatalf("findDBPath() error = %v", err)
	}
	if got != physical {
		t.Fatalf("findDBPath() = %q, want %q", got, physical)
	}
}

func TestFindDBPathPhysicalIsDirectoryShortCircuits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir() // a directory, not a regular file

	_, err := findDBPath(dir, failDockerFallback(t))
	if err == nil {
		t.Fatal("findDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to access physical pi-hole DB") {
		t.Fatalf("findDBPath() error = %q, want it to mention accessing the physical DB", err)
	}
}

func TestFindDBPathFallsBackToDockerWhenPhysicalMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missingPhysical := filepath.Join(dir, "nope.db")
	dockerPath := filepath.Join(dir, "docker-mounted.db")

	got, err := findDBPath(missingPhysical, func() (string, error) {
		return dockerPath, nil
	})
	if err != nil {
		t.Fatalf("findDBPath() error = %v", err)
	}
	if got != dockerPath {
		t.Fatalf("findDBPath() = %q, want %q", got, dockerPath)
	}
}

func TestFindDBPathBothMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missingPhysical := filepath.Join(dir, "nope.db")

	_, err := findDBPath(missingPhysical, func() (string, error) {
		return "", errors.New("no running pi-hole container found")
	})
	if err == nil {
		t.Fatal("findDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "pi-hole not found") {
		t.Fatalf("findDBPath() error = %q, want it to mention 'pi-hole not found'", err)
	}
}

// ---- findPiholeContainer ------------------------------------------------

func TestFindPiholeContainerMatchesByName(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo \"abc123\tmy-pihole-1\tsomeimage:latest\" ;;\nesac\n")

	id, err := findPiholeContainer()
	if err != nil {
		t.Fatalf("findPiholeContainer() error = %v", err)
	}
	if id != "abc123" {
		t.Fatalf("findPiholeContainer() = %q, want %q", id, "abc123")
	}
}

func TestFindPiholeContainerMatchesByImage(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo \"def456\tunrelated-name\tpihole/pihole:2024.07.0\" ;;\nesac\n")

	id, err := findPiholeContainer()
	if err != nil {
		t.Fatalf("findPiholeContainer() error = %v", err)
	}
	if id != "def456" {
		t.Fatalf("findPiholeContainer() = %q, want %q", id, "def456")
	}
}

func TestFindPiholeContainerCaseInsensitive(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo \"ghi789\tMyPiHoleBox\tSomeImage\" ;;\nesac\n")

	id, err := findPiholeContainer()
	if err != nil {
		t.Fatalf("findPiholeContainer() error = %v", err)
	}
	if id != "ghi789" {
		t.Fatalf("findPiholeContainer() = %q, want %q", id, "ghi789")
	}
}

func TestFindPiholeContainerNoneFound(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo \"xyz999\tunrelated\tother/image\" ;;\nesac\n")

	_, err := findPiholeContainer()
	if err == nil {
		t.Fatal("findPiholeContainer() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "no running pi-hole container found") {
		t.Fatalf("findPiholeContainer() error = %q, want it to mention no container found", err)
	}
}

func TestFindPiholeContainerDockerNotRunning(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\necho \"cannot connect to the docker daemon\" >&2\nexit 1\n")

	_, err := findPiholeContainer()
	if err == nil {
		t.Fatal("findPiholeContainer() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "docker ps failed") {
		t.Fatalf("findPiholeContainer() error = %q, want it to mention 'docker ps failed'", err)
	}
}

// ---- findDockerDBPath -------------------------------------------------

func TestFindDockerDBPathSuccess(t *testing.T) {
	mountDir := t.TempDir()
	writeRegularFile(t, filepath.Join(mountDir, ftlDBFilename))

	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n"+
		"  ps) echo \"cid1\tmy-pihole\tpihole/pihole\" ;;\n"+
		"  inspect) echo '[{\"Source\":\""+mountDir+"\",\"Destination\":\"/etc/pihole\"}]' ;;\n"+
		"esac\n")

	got, err := findDockerDBPath()
	if err != nil {
		t.Fatalf("findDockerDBPath() error = %v", err)
	}
	want := filepath.Join(mountDir, ftlDBFilename)
	if got != want {
		t.Fatalf("findDockerDBPath() = %q, want %q", got, want)
	}
}

func TestFindDockerDBPathNoPiholeMount(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n"+
		"  ps) echo \"cid1\tmy-pihole\tpihole/pihole\" ;;\n"+
		"  inspect) echo '[{\"Source\":\"/some/other\",\"Destination\":\"/var/lib/other\"}]' ;;\n"+
		"esac\n")

	_, err := findDockerDBPath()
	if err == nil {
		t.Fatal("findDockerDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "no /etc/pihole mount detected") {
		t.Fatalf("findDockerDBPath() error = %q, want it to mention no mount detected", err)
	}
}

func TestFindDockerDBPathMountedButDBMissing(t *testing.T) {
	mountDir := t.TempDir() // no pihole-FTL.db written inside

	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n"+
		"  ps) echo \"cid1\tmy-pihole\tpihole/pihole\" ;;\n"+
		"  inspect) echo '[{\"Source\":\""+mountDir+"\",\"Destination\":\"/etc/pihole\"}]' ;;\n"+
		"esac\n")

	_, err := findDockerDBPath()
	if err == nil {
		t.Fatal("findDockerDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "DB not available at expected path") {
		t.Fatalf("findDockerDBPath() error = %q, want it to mention DB not available", err)
	}
}

func TestFindDockerDBPathContainerNotFound(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n  ps) echo \"cid1\tunrelated\tother/image\" ;;\nesac\n")

	_, err := findDockerDBPath()
	if err == nil {
		t.Fatal("findDockerDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "no running pi-hole container found") {
		t.Fatalf("findDockerDBPath() error = %q, want it to propagate the container-not-found error", err)
	}
}

func TestFindDockerDBPathInspectFails(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n"+
		"  ps) echo \"cid1\tmy-pihole\tpihole/pihole\" ;;\n"+
		"  inspect) echo \"no such container\" >&2; exit 1 ;;\n"+
		"esac\n")

	_, err := findDockerDBPath()
	if err == nil {
		t.Fatal("findDockerDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "docker inspect failed") {
		t.Fatalf("findDockerDBPath() error = %q, want it to mention 'docker inspect failed'", err)
	}
}

func TestFindDockerDBPathMalformedInspectJSON(t *testing.T) {
	installFakeDocker(t, "#!/bin/sh\ncase \"$1\" in\n"+
		"  ps) echo \"cid1\tmy-pihole\tpihole/pihole\" ;;\n"+
		"  inspect) echo \"not json at all\" ;;\n"+
		"esac\n")

	_, err := findDockerDBPath()
	if err == nil {
		t.Fatal("findDockerDBPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to parse docker inspect output") {
		t.Fatalf("findDockerDBPath() error = %q, want it to mention JSON parse failure", err)
	}
}
