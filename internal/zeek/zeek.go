// Package zeek tails Zeek logs to extract SNI/domain data and DNS-bypass notices.
package zeek

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	tickInterval = 5 * time.Second
	entryExpiry  = 2 * time.Minute
)

// Config holds the configuration for the Zeek ssl.log tailer.
type Config struct {
	LogPath string
}

type sniEntry struct {
	domain     string
	observedAt time.Time
}

// sslRecord is the subset of fields extracted from a Zeek SSL log line when
// that line is JSON (LogAscii::use_json = T). Zeek's default output is
// tab-separated, not JSON — see recordFromLine and parseTSVFieldsLine for
// that path, which is what a stock Zeek install actually produces.
type sslRecord struct {
	OrigH      string `json:"id.orig_h"`
	OrigP      any    `json:"id.orig_p"`
	RespH      string `json:"id.resp_h"`
	RespP      any    `json:"id.resp_p"`
	ServerName string `json:"server_name"`
}

// Client tails a Zeek ssl.log and maintains a short-lived in-memory cache
// mapping connection tuples to their observed SNI domain.
type Client struct {
	logPath string

	mu    sync.RWMutex
	cache map[string]sniEntry

	// tsvFields maps a Zeek TSV column name (e.g. "id.orig_h") to its column
	// index, learned from a "#fields" header line. nil until one has been
	// seen for the current file, in which case non-JSON lines can't yet be
	// interpreted and are skipped.
	tsvFields map[string]int

	offset  int64
	pending []byte // bytes read past the last newline; held until the rest of the line arrives
	stopCh  chan struct{}
	done    chan struct{}
}

// NewClient opens the ssl.log at the configured path and starts a
// background goroutine that tails new lines, in either of Zeek's log
// formats (TSV, the default; or JSON, if LogAscii::use_json is set).
// If cfg is nil or LogPath is empty, it returns nil without error.
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil || strings.TrimSpace(cfg.LogPath) == "" {
		return nil, nil
	}

	logPath := strings.TrimSpace(cfg.LogPath)

	// Verify the file exists and is readable before starting the tailer.
	f, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zeek ssl.log %s: %w", logPath, err)
	}

	fi, err := f.Stat()

	_ = f.Close()

	if err != nil {
		return nil, fmt.Errorf("failed to stat zeek ssl.log %s: %w", logPath, err)
	}

	c := &Client{
		logPath: logPath,
		cache:   make(map[string]sniEntry),
		offset:  fi.Size(),
		// The tailer starts reading from the current end of the file (above),
		// which is always past the "#fields" header Zeek writes once, at the
		// very top, when it first creates the log. Without this separate,
		// from-the-start read, TSV parsing would never learn the column
		// order in the normal case (Zeek already running before hexwall
		// starts) and would silently never match anything.
		tsvFields: readTSVHeader(logPath),
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}

	go c.tailLoop(context.Background())

	slog.Info("zeek log watcher started", "path", logPath, "offset", c.offset, "tsv_header_found", c.tsvFields != nil)

	return c, nil
}

// Close stops the background tailer and waits for it to finish.
func (c *Client) Close() {
	if c == nil {
		return
	}

	close(c.stopCh)

	<-c.done
}

// Lookup returns the SNI domain observed for the given connection tuple,
// or ("", false) if no matching record exists in the cache.
func (c *Client) Lookup(localPort, remoteIP, remotePort string) (string, bool) {
	// A nil *Client stored in an interface is not a nil interface, so callers holding one
	// can't tell it apart from a real client: answer "no SNI" instead of panicking.
	if c == nil {
		return "", false
	}
	key := localPort + "|" + remoteIP + "|" + remotePort

	c.mu.RLock()
	entry, ok := c.cache[key]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	if time.Since(entry.observedAt) > entryExpiry {
		return "", false
	}

	return entry.domain, true
}

// parseTSVFieldsLine parses a Zeek "#fields\t..." header line into a
// column-name -> index map. Returns nil for any other line, including other
// "#"-prefixed header metadata (#separator, #path, #open, ...).
func parseTSVFieldsLine(line string) map[string]int {
	if !strings.HasPrefix(line, "#fields\t") {
		return nil
	}

	cols := strings.Split(line, "\t")
	fields := make(map[string]int, len(cols)-1)
	for i, name := range cols[1:] {
		fields[name] = i
	}

	return fields
}

// readTSVHeader scans from the start of the log file for a "#fields" header
// line. Returns nil if the file isn't in TSV format (e.g. it's JSON, or
// reading fails), in which case the caller falls back to per-line JSON
// detection only.
func readTSVHeader(logPath string) map[string]int {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if fields := parseTSVFieldsLine(line); fields != nil {
			return fields
		}
		if !strings.HasPrefix(line, "#") {
			return nil // reached a data line without finding #fields
		}
	}

	return nil
}

// recordFromLine extracts the five ssl.log fields this package needs from a
// single log line, transparently handling both of Zeek's log formats:
//
//   - TSV (Zeek's default): a "#fields" header line, seen once per file,
//     declares the column order; every following line is read positionally
//     against it via c.tsvFields. Any other "#"-prefixed line is header
//     metadata and is skipped. A "#fields" line seen here (not just at
//     NewClient time) updates c.tsvFields — this is what makes a rotated
//     log's fresh header get picked up too.
//   - JSON (LogAscii::use_json = T): each line is a self-describing object.
//
// ok is false for header lines, or for a TSV data line seen before its
// header (data missing "-" is normalized to "", matching Zeek's own
// unset-field marker).
func (c *Client) recordFromLine(line string) (origH, origP, respH, respP, serverName string, ok bool) {
	switch {
	case strings.HasPrefix(line, "#"):
		if fields := parseTSVFieldsLine(line); fields != nil {
			c.tsvFields = fields
		}
		return "", "", "", "", "", false

	case strings.HasPrefix(line, "{"):
		var rec sslRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return "", "", "", "", "", false
		}
		return rec.OrigH, fmt.Sprint(rec.OrigP), rec.RespH, fmt.Sprint(rec.RespP), rec.ServerName, true

	default:
		if c.tsvFields == nil {
			return "", "", "", "", "", false
		}

		cols := strings.Split(line, "\t")
		get := func(name string) string {
			i, ok := c.tsvFields[name]
			if !ok || i >= len(cols) {
				return ""
			}
			if cols[i] == "-" { // Zeek's unset-field marker
				return ""
			}
			return cols[i]
		}

		return get("id.orig_h"), get("id.orig_p"), get("id.resp_h"), get("id.resp_p"), get("server_name"), true
	}
}

func (c *Client) tailLoop(ctx context.Context) {
	defer close(c.done)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.processNewLines()
		}
	}
}

func (c *Client) processNewLines() {
	file, err := os.Open(c.logPath)
	if err != nil {
		slog.Debug("zeek: cannot open ssl.log", "path", c.logPath, "err", err)
		return
	}

	defer func() {
		if err := file.Close(); err != nil {
			slog.Debug("zeek: failed to close ssl.log", "path", c.logPath, "err", err)
		}
	}()

	fi, err := file.Stat()
	if err != nil {
		slog.Debug("zeek: cannot stat ssl.log", "path", c.logPath, "err", err)
		return
	}

	// File was likely rotated — reset to the beginning and drop any
	// partial line held over from the old file. The new file's own
	// "#fields" header will be re-learned via recordFromLine below as the
	// tailer reads through it, same as any other line.
	if fi.Size() < c.offset {
		c.offset = 0
		c.pending = nil
	}

	if fi.Size() == c.offset {
		return
	}

	if _, err := file.Seek(c.offset, io.SeekStart); err != nil {
		slog.Debug("zeek: seek failed", "path", c.logPath, "err", err)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		slog.Debug("zeek: read failed", "path", c.logPath, "err", err)
		return
	}

	// We've now consumed everything up to fi.Size() from the file, even
	// if the trailing bytes don't yet form a complete line — hold them in
	// pending rather than losing them, since Zeek may still be mid-write
	// on the last line when this tick fires.
	c.offset = fi.Size()

	buf := append(c.pending, data...)
	lastNewline := bytes.LastIndexByte(buf, '\n')
	if lastNewline == -1 {
		c.pending = buf
		return
	}

	complete := buf[:lastNewline]
	c.pending = append([]byte(nil), buf[lastNewline+1:]...)

	lines := strings.Split(string(complete), "\n")

	c.mu.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		origH, origP, respH, respP, serverName, ok := c.recordFromLine(line)
		if !ok || serverName == "" || origH == "" || respH == "" {
			continue
		}

		now := time.Now()
		entry := sniEntry{domain: serverName, observedAt: now}

		// Store both orientations so Lookup works regardless of which
		// side of the connection is the local endpoint.
		c.cache[origP+"|"+respH+"|"+respP] = entry
		c.cache[respP+"|"+origH+"|"+origP] = entry
	}

	// Prune expired entries.
	cutoff := time.Now().Add(-entryExpiry)
	for k, v := range c.cache {
		if v.observedAt.Before(cutoff) {
			delete(c.cache, k)
		}
	}
	c.mu.Unlock()
}
