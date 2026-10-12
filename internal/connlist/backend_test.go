package connlist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeBinary writes an executable script into dir under the given name.
func writeFakeBinary(t *testing.T, dir, name, script string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

func TestSelectBackend(t *testing.T) {
	okScript := "#!/bin/sh\nexit 0\n"

	tests := []struct {
		name     string
		binaries []string // names to place on an otherwise-empty PATH
		wantName string
		wantErr  bool
	}{
		{name: "ss present picks ss", binaries: []string{"ss", "somo"}, wantName: "ss"},
		{name: "only somo present picks somo", binaries: []string{"somo"}, wantName: "somo"},
		{name: "neither present fails", binaries: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, bin := range tt.binaries {
				writeFakeBinary(t, dir, bin, okScript)
			}

			t.Setenv("PATH", dir)

			lister, name, err := SelectBackend()
			if tt.wantErr {
				if err == nil {
					t.Fatal("SelectBackend() error = nil, want error")
				}

				return
			}

			if err != nil {
				t.Fatalf("SelectBackend() error = %v, want nil", err)
			}

			if name != tt.wantName {
				t.Fatalf("SelectBackend() name = %q, want %q", name, tt.wantName)
			}

			if lister == nil {
				t.Fatal("SelectBackend() lister = nil, want non-nil")
			}
		})
	}
}

// ---- selectBackend: macOS never probes for ss ---------------------------

func TestSelectBackendDarwinNeverCallsSSAvailable(t *testing.T) {
	t.Parallel()

	ssAvailableCalled := func() bool {
		t.Error("ssAvailable() was called on darwin, want it never probed")
		return true
	}
	somoInstalled := func() error { return nil }

	_, name, err := selectBackend("darwin", ssAvailableCalled, somoInstalled)
	if err != nil {
		t.Fatalf("selectBackend(darwin) error = %v, want nil", err)
	}

	if name != "somo" {
		t.Fatalf("selectBackend(darwin) name = %q, want %q (ss must never be picked on darwin, even if it claims available)", name, "somo")
	}
}

func TestSelectBackendDarwinFailureMessageOmitsSS(t *testing.T) {
	t.Parallel()

	_, _, err := selectBackend("darwin", func() bool { return false }, func() error { return errors.New("not found") })
	if err == nil {
		t.Fatal("selectBackend(darwin) error = nil, want error when somo is also missing")
	}

	if !strings.Contains(err.Error(), "somo") {
		t.Fatalf("selectBackend(darwin) error = %q, want it to mention somo", err)
	}

	if strings.Contains(err.Error(), "install ss") {
		t.Fatalf("selectBackend(darwin) error = %q, want it to NOT suggest installing ss on macOS", err)
	}
}

func TestSelectBackendLinuxUnaffected(t *testing.T) {
	t.Parallel()

	lister, name, err := selectBackend("linux", func() bool { return true }, func() error { return nil })
	if err != nil {
		t.Fatalf("selectBackend(linux) error = %v, want nil", err)
	}

	if name != "ss" {
		t.Fatalf("selectBackend(linux) name = %q, want %q", name, "ss")
	}

	if lister == nil {
		t.Fatal("selectBackend(linux) lister = nil, want non-nil")
	}
}

func TestSelectBackendLinuxFailureMessageMentionsBoth(t *testing.T) {
	t.Parallel()

	_, _, err := selectBackend("linux", func() bool { return false }, func() error { return errors.New("not found") })
	if err == nil {
		t.Fatal("selectBackend(linux) error = nil, want error")
	}

	if !strings.Contains(err.Error(), "ss") || !strings.Contains(err.Error(), "somo") {
		t.Fatalf("selectBackend(linux) error = %q, want it to mention both ss and somo", err)
	}
}
