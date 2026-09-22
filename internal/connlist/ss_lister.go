package connlist

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// processFieldPattern extracts the first "prog",pid=N entry from ss's
// users:(("prog",pid=N,fd=M),...) process column. Only the first owner is
// kept, matching somo's one-program-per-connection shape.
var processFieldPattern = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+),fd=\d+\)`)

// SSAvailable reports whether the ss CLI (iproute2) is available in PATH.
func SSAvailable() bool {
	_, err := exec.LookPath("ss")
	return err == nil
}

// GetEstablishedConnectionsViaSS lists established TCP connections using ss,
// the preferred backend when iproute2 is available (Linux, not macOS).
func GetEstablishedConnectionsViaSS() ([]Connection, error) {
	cmd := exec.Command("ss", "-H", "-tnp", "state", "established")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, commandError("failed to run ss", err, output)
	}

	return parseSSOutput(string(output)), nil
}

// parseSSOutput parses `ss -H -tnp state established` output into Connections.
// A malformed line is skipped rather than aborting the whole parse. A
// connection whose owning process ss couldn't identify (no users:(...) field,
// e.g. owned by another user without CAP_NET_ADMIN) yields an empty
// Program/PID, since enforcer.ParsePID already treats "" as invalid.
func parseSSOutput(output string) []Connection {
	var connections []Connection

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		_, localPort, err := splitSSAddress(fields[2])
		if err != nil {
			continue
		}
		remoteHost, remotePort, err := splitSSAddress(fields[3])
		if err != nil {
			continue
		}

		conn := Connection{
			Protocol: "tcp",
			LPort:    localPort,
			RAddress: remoteHost,
			RPort:    remotePort,
			State:    "ESTAB",
		}

		if len(fields) >= 5 {
			if m := processFieldPattern.FindStringSubmatch(fields[4]); m != nil {
				conn.Program = m[1]
				conn.PID = m[2]
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

// splitSSAddress splits ss's "host:port" (or "[ipv6]:port") address column.
func splitSSAddress(field string) (host, port string, err error) {
	idx := strings.LastIndex(field, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("no port separator in address %q", field)
	}

	host, port = field[:idx], field[idx+1:]
	if host == "" || port == "" {
		return "", "", fmt.Errorf("empty host or port in address %q", field)
	}

	return host, port, nil
}
