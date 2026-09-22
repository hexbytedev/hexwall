package connlist

import (
	"os"
	"path/filepath"
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
