// Package somo wraps the somo CLI for monitoring and managing network connections.
package somo

import (
	"encoding/json"
	"fmt"
	"os/exec"
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

// GetEstablishedConnections returns a list of established TCP/UDP connections.
func GetEstablishedConnections() ([]Connection, error) {
	cmd := exec.Command("somo", "-e", "--json", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run somo: %w", err)
	}

	var result []Connection
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return result, nil
}

// KillConnection kills a process by PID via somo.
func KillConnection(pid string) error {
	if pid == "-" || pid == "" {
		return fmt.Errorf("invalid PID: %s", pid)
	}

	cmd := exec.Command("somo", "-k", "-p", pid)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to kill connection with PID %s: %w", pid, err)
	}

	return nil
}
