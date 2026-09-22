package connlist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeSomo writes an executable shell script named "somo" into a temp
// directory and prepends that directory to PATH, so exec.LookPath("somo") and
// exec.Command("somo", ...) resolve to the fake instead of a real install.
func installFakeSomo(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "somo")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake somo: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestCheckInstalledSucceedsWhenOnPath(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\nexit 0\n")

	if err := CheckInstalled(); err != nil {
		t.Fatalf("CheckInstalled() error = %v, want nil", err)
	}
}

func TestCheckInstalledFailsWhenPathEmpty(t *testing.T) {
	t.Setenv("PATH", "")

	if err := CheckInstalled(); err == nil {
		t.Fatal("CheckInstalled() error = nil, want error for empty PATH")
	}
}

func TestCheckInstalledFailsWhenNotOnPath(t *testing.T) {
	// A PATH pointing only at an empty directory has no somo binary.
	t.Setenv("PATH", t.TempDir())

	if err := CheckInstalled(); err == nil {
		t.Fatal("CheckInstalled() error = nil, want error when somo is not on PATH")
	}
}

func TestGetEstablishedConnectionsParsesAllFields(t *testing.T) {
	installFakeSomo(t, `#!/bin/sh
echo '[{"proto":"tcp","local_port":"51820","remote_address":"203.0.113.10","remote_port":"443","program":"curl","pid":"1234","state":"ESTABLISHED","address_type":"ipv4"}]'
`)

	conns, err := GetEstablishedConnections()
	if err != nil {
		t.Fatalf("GetEstablishedConnections() error = %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("GetEstablishedConnections() len = %d, want 1", len(conns))
	}

	want := Connection{
		Protocol:    "tcp",
		LPort:       "51820",
		RAddress:    "203.0.113.10",
		RPort:       "443",
		Program:     "curl",
		PID:         "1234",
		State:       "ESTABLISHED",
		AddressType: "ipv4",
	}
	if conns[0] != want {
		t.Fatalf("GetEstablishedConnections()[0] = %+v, want %+v", conns[0], want)
	}
}

func TestGetEstablishedConnectionsEmptyArray(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\necho '[]'\n")

	conns, err := GetEstablishedConnections()
	if err != nil {
		t.Fatalf("GetEstablishedConnections() error = %v", err)
	}
	if len(conns) != 0 {
		t.Fatalf("GetEstablishedConnections() len = %d, want 0", len(conns))
	}
}

func TestGetEstablishedConnectionsMalformedJSON(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\necho 'not json'\n")

	_, err := GetEstablishedConnections()
	if err == nil {
		t.Fatal("GetEstablishedConnections() error = nil, want error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("GetEstablishedConnections() error = %q, want it to mention %q", err.Error(), "failed to parse")
	}
}

func TestGetEstablishedConnectionsNonZeroExit(t *testing.T) {
	installFakeSomo(t, "#!/bin/sh\necho 'somo: permission denied' 1>&2\nexit 1\n")

	_, err := GetEstablishedConnections()
	if err == nil {
		t.Fatal("GetEstablishedConnections() error = nil, want error for non-zero exit")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("GetEstablishedConnections() error = %q, want it to include command output", err.Error())
	}
}

func TestCommandError(t *testing.T) {
	t.Parallel()

	wrapped := errors.New("exit status 1")

	tests := []struct {
		name    string
		message string
		err     error
		output  []byte
		want    string
	}{
		{
			name:    "empty output",
			message: "failed to run somo",
			err:     wrapped,
			output:  nil,
			want:    "failed to run somo: exit status 1",
		},
		{
			name:    "whitespace-only output",
			message: "failed to run somo",
			err:     wrapped,
			output:  []byte("   \n\t  "),
			want:    "failed to run somo: exit status 1",
		},
		{
			name:    "non-empty output",
			message: "failed to run somo",
			err:     wrapped,
			output:  []byte("permission denied\n"),
			want:    "failed to run somo: exit status 1: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := commandError(tt.message, tt.err, tt.output)
			if got.Error() != tt.want {
				t.Fatalf("commandError() = %q, want %q", got.Error(), tt.want)
			}
			if !errors.Is(got, wrapped) {
				t.Fatal("commandError() does not wrap the original error")
			}
		})
	}
}
