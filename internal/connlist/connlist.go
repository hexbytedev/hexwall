// Package connlist lists established network connections via ss (preferred)
// or somo (fallback) — see SelectBackend.
package connlist

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Connection matches somo's default JSON output.
type Connection struct {
	Protocol    string `json:"proto"`
	LPort       string `json:"local_port"`
	RAddress    string `json:"remote_address"`
	RPort       string `json:"remote_port"`
	Program     string `json:"program"`
	PID         string `json:"pid"`
	State       string `json:"state"`
	AddressType string `json:"address_type"`
}

// CheckInstalled reports whether the somo CLI is available in PATH.
func CheckInstalled() error {
	_, err := exec.LookPath("somo")
	if err != nil {
		return fmt.Errorf("somo is not installed in the path: %w", err)
	}

	return nil
}

// SelectBackend picks a connection-listing tool by availability: ss
// (iproute2) first since it needs no extra install on virtually any Linux
// box, falling back to somo when ss isn't on PATH (e.g. macOS). name is
// "ss" or "somo", for logging which tool is in effect.
func SelectBackend() (lister func() ([]Connection, error), name string, err error) {
	if SSAvailable() {
		return GetEstablishedConnectionsViaSS, "ss", nil
	}

	if CheckInstalled() == nil {
		return GetEstablishedConnections, "somo", nil
	}

	return nil, "", fmt.Errorf("no connection-listing tool available: install ss (iproute2) or somo (https://github.com/theopfr/somo)")
}

// GetEstablishedConnections returns a list of established TCP/UDP connections.
func GetEstablishedConnections() ([]Connection, error) {
	cmd := exec.Command("somo", "-e", "--json", "--no-pager")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, commandError("failed to run somo", err, output)
	}

	var result []Connection
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse somo JSON: %w", err)
	}

	return result, nil
}

func commandError(message string, err error, output []byte) error {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return fmt.Errorf("%s: %w", message, err)
	}

	return fmt.Errorf("%s: %w: %s", message, err, trimmed)
}
