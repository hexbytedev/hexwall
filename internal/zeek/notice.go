package zeek

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

var (
	// ErrNoticeLineEmpty indicates a notice log line was blank.
	ErrNoticeLineEmpty = errors.New("empty notice line")
	// ErrNoticeLineNoFields indicates a notice log line parsed as JSON but had none of the recognized fields.
	ErrNoticeLineNoFields = errors.New("notice line did not contain recognizable fields")
)

// Event is a parsed DNS bypass notice from Zeek.
type Event struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	DstPort   string
	SNI       string
}

// ParseNoticeLine parses a single Zeek notice JSON line into an Event.
func ParseNoticeLine(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, ErrNoticeLineEmpty
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return Event{}, fmt.Errorf("parse notice line: %w", err)
	}

	event := Event{
		Timestamp: time.Now(),
	}

	if ts, ok := payload["ts"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = parsed
		}
	}

	if ts, ok := payload["timestamp"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = parsed
		}
	}

	event.SrcIP = stringValue(payload["src_ip"], payload["src"], payload["id.orig_h"])
	event.DstIP = stringValue(payload["dst_ip"], payload["dst"], payload["id.resp_h"])
	event.DstPort = stringValue(payload["dst_port"], payload["p"], payload["id.resp_p"])
	event.SNI = stringValue(payload["sni"], payload["server_name"])

	if event.SrcIP == "" && event.DstIP == "" && event.SNI == "" {
		return Event{}, ErrNoticeLineNoFields
	}

	return event, nil
}

// WatchNoticeLog tails a Zeek notice log and emits parsed Events.
func WatchNoticeLog(ctx context.Context, path string, events chan<- Event) error {
	logPath := strings.TrimSpace(path)
	if ctx == nil || logPath == "" {
		return nil
	}

	var offset int64
	poller := time.NewTicker(2 * time.Second)
	defer poller.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poller.C:
			file, err := os.Open(logPath)
			if err != nil {
				slog.Debug("zeek: cannot open notice log", "path", logPath, "err", err)
				continue
			}

			fi, err := file.Stat()
			if err != nil {
				_ = file.Close()
				slog.Debug("zeek: cannot stat notice log", "path", logPath, "err", err)
				continue
			}

			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() > offset {
				if _, err := file.Seek(offset, io.SeekStart); err != nil {
					_ = file.Close()
					slog.Debug("zeek: seek notice log failed", "path", logPath, "err", err)
					continue
				}

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}

					event, err := ParseNoticeLine(line)
					if err != nil {
						continue
					}

					select {
					case events <- event:
					default:
					}
				}
				if err := scanner.Err(); err != nil {
					slog.Debug("zeek: notice log scan failed", "path", logPath, "err", err)
				}
			}
			_ = file.Close()
			offset = fi.Size()
		}
	}
}

func stringValue(values ...any) string {
	for _, value := range values {
		switch v := value.(type) {
		case string:
			return strings.TrimSpace(v)
		case fmt.Stringer:
			return strings.TrimSpace(v.String())
		case nil:
			continue
		default:
			return fmt.Sprint(v)
		}
	}
	return ""
}
