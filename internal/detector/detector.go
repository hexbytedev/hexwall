// Package detector handles auto-discovery of the Pi-hole FTL database path.
// It checks for a physical (bare-metal) installation first, then falls back
// to a Docker-based installation.
package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	physicalDBPath = "/etc/pihole/pihole-FTL.db"
	ftlDBFilename  = "pihole-FTL.db"
)

// FindDBPath returns the path to pihole-FTL.db by checking:
//  1. Physical installation at /etc/pihole/pihole-FTL.db
//  2. Docker container with "pihole" in the name or image
//
// Returns an error if neither is found.
func FindDBPath() (string, error) {
	// 1. Physical installation
	if _, err := os.Stat(physicalDBPath); err == nil {
		return physicalDBPath, nil
	}

	// 2. Docker installation
	path, err := findDockerDBPath()
	if err != nil {
		return "", fmt.Errorf(
			"pi-hole not found: no physical installation at %s and no running pi-hole Docker container (%w)",
			physicalDBPath, err,
		)
	}

	return path, nil
}

// dockerMount represents a single entry from docker inspect's Mounts array.
type dockerMount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

func findDockerDBPath() (string, error) {
	// Find running Pi-hole containers by name or image
	containerID, err := findPiholeContainer()
	if err != nil {
		return "", err
	}

	// Inspect the container to find where /etc/pihole is mounted on the host
	out, err := exec.Command("docker", "inspect", "--format", "{{json .Mounts}}", containerID).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect failed for container %s: %w", containerID, err)
	}

	var mounts []dockerMount
	if err := json.Unmarshal(out, &mounts); err != nil {
		return "", fmt.Errorf("failed to parse docker inspect output: %w", err)
	}

	for _, m := range mounts {
		if m.Destination == "/etc/pihole" {
			dbPath := filepath.Join(m.Source, ftlDBFilename)
			if _, err := os.Stat(dbPath); err != nil {
				return "", fmt.Errorf("pi-hole container found but DB not at expected path %s: %w", dbPath, err)
			}

			return dbPath, nil
		}
	}

	return "", fmt.Errorf("pi-hole container %s found but no /etc/pihole mount detected", containerID)
}

// findPiholeContainer returns the container ID of a running Pi-hole container.
// It matches against container names and image names containing "pihole".
func findPiholeContainer() (string, error) {
	out, err := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}").Output()
	if err != nil {
		return "", fmt.Errorf("docker ps failed (is Docker running?): %w", err)
	}

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}

		id, name, image := parts[0], parts[1], parts[2]
		if strings.Contains(strings.ToLower(name), "pihole") ||
			strings.Contains(strings.ToLower(image), "pihole") {
			return id, nil
		}
	}

	return "", fmt.Errorf("no running pi-hole container found")
}
