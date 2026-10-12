package zeek

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// DNSBypassScript is the Zeek script that writes the notices this file reads. It ships
// inside the hexwall binary (installed by `hexwall zeek-setup`) so the script and this
// parser can never drift apart: the script puts the SNI in the notice's sub field, and
// parseLine reads it from there.
//
//go:embed dns-bypass.zeek
var DNSBypassScript []byte

// bypassNote is the notice type raised by DNSBypassScript. notice.log carries every Zeek
// notice (invalid certificates, scans, ...); only this one is a DNS-bypass alert.
const bypassNote = "DNSBypass::PossibleBypass"

var (
	// ErrNoticeHeaderMissing indicates a TSV data line arrived before the "#fields" header that names its columns.
	ErrNoticeHeaderMissing = errors.New("tsv notice line before its #fields header")
	// ErrNoticeNoSNI indicates a DNS-bypass notice with no SNI in its sub field, e.g. one
	// written by an older copy of the Zeek script; re-running `hexwall zeek-setup` fixes it.
	ErrNoticeNoSNI = errors.New("dns-bypass notice without an SNI in sub; re-run hexwall zeek-setup")
)

// Event is a parsed DNS bypass notice from Zeek.
type Event struct {
	Timestamp time.Time
	SrcIP     string
	SrcPort   string
	DstIP     string
	DstPort   string
	SNI       string
}

// noticeParser turns notice.log lines into Events, in either of Zeek's log formats: TSV
// (the default), read against the column order of the file's "#fields" header, or JSON
// (LogAscii::use_json = T). It remembers the header between calls, so it must be fed one
// file's lines in order.
type noticeParser struct {
	tsvFields map[string]int
}

// parseLine returns ok=false with a nil error for lines that are not DNS-bypass alerts:
// blank lines, header lines, and other notice types.
func (p *noticeParser) parseLine(line string) (event Event, ok bool, err error) {
	line = strings.TrimSuffix(line, "\r")
	switch {
	case strings.TrimSpace(line) == "":
		return Event{}, false, nil
	case strings.HasPrefix(line, "#"):
		if fields := parseTSVFieldsLine(line); fields != nil {
			p.tsvFields = fields
		}

		return Event{}, false, nil
	}

	fields, err := p.fields(line)
	if err != nil {
		return Event{}, false, err
	}

	if fields["note"] != bypassNote {
		return Event{}, false, nil
	}

	if fields["sub"] == "" {
		return Event{}, false, ErrNoticeNoSNI
	}

	return Event{
		Timestamp: parseZeekTime(fields["ts"]),
		SrcIP:     firstNonEmpty(fields["src"], fields["id.orig_h"]),
		SrcPort:   fields["id.orig_p"],
		DstIP:     firstNonEmpty(fields["dst"], fields["id.resp_h"]),
		DstPort:   firstNonEmpty(fields["p"], fields["id.resp_p"]),
		SNI:       fields["sub"],
	}, true, nil
}

// fields maps column name to value for one data line. Unset values are left out.
func (p *noticeParser) fields(line string) (map[string]string, error) {
	if strings.HasPrefix(line, "{") {
		decoder := json.NewDecoder(strings.NewReader(line))
		// Keeps ts as "1398362902.726337" rather than a float64 printed as 1.398362902726337e+09.
		decoder.UseNumber()

		var payload map[string]any
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("parse json notice line: %w", err)
		}

		fields := make(map[string]string, len(payload))
		for name, value := range payload {
			fields[name] = fmt.Sprint(value)
		}

		return fields, nil
	}

	if p.tsvFields == nil {
		return nil, ErrNoticeHeaderMissing
	}

	cols := strings.Split(line, "\t")

	fields := make(map[string]string, len(p.tsvFields))
	for name, i := range p.tsvFields {
		// "-" is Zeek's unset-field marker, "(empty)" its empty-set marker.
		if i < len(cols) && cols[i] != "-" && cols[i] != "(empty)" {
			fields[name] = cols[i]
		}
	}

	return fields, nil
}

// parseZeekTime reads Zeek's default epoch-seconds timestamp, or an RFC 3339 one (the
// LogAscii::json_timestamps option). It falls back to now so an event is never undated.
func parseZeekTime(value string) time.Time {
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		whole, frac := math.Modf(seconds)
		return time.Unix(int64(whole), int64(frac*1e9))
	}

	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed
	}

	return time.Now()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// noticeTailer reads notice.log from where it last stopped.
type noticeTailer struct {
	path          string
	offset        int64
	parser        noticeParser
	warnedBadLine bool
	state         fileState // what was last reported about the file, so each change is logged once
}

// fileState is what the tailer last found at its path.
type fileState int

const (
	fileUnchecked  fileState = iota
	fileMissing              // Zeek writes notice.log at its first alert, so this is normal for a while
	fileUnreadable           // exists but can't be opened, e.g. permissions
	fileOpen
)

// skipExisting reads the file as it is now without sending anything: the parser still
// learns the TSV "#fields" header at the top, but alerts already in the file are not
// replayed. In enforce mode an old alert would otherwise trigger a kill on every restart.
func (t *noticeTailer) skipExisting() {
	t.read(nil)
}

// poll reads every complete line added since the last poll and sends its DNS-bypass alerts.
func (t *noticeTailer) poll(events chan<- Event) {
	t.read(events)
}

// read consumes the complete lines past t.offset. With a nil events channel it only
// advances the offset and the parser's header.
func (t *noticeTailer) read(events chan<- Event) {
	file, err := os.Open(t.path)
	if err != nil {
		t.reportOpenError(err)
		return
	}
	defer func() { _ = file.Close() }()

	if t.state != fileOpen {
		slog.Info("zeek: notice log found, watching for DNS-bypass alerts", "path", t.path)
		t.state = fileOpen
	}

	fi, err := file.Stat()
	if err != nil {
		slog.Debug("zeek: cannot stat notice log", "path", t.path, "err", err)
		return
	}

	// Smaller than what was already read: the log was rotated. The new file starts with
	// its own header, so forget the old one too.
	if fi.Size() < t.offset {
		t.offset = 0
		t.parser = noticeParser{}
	}

	if fi.Size() == t.offset {
		return
	}

	if _, err := file.Seek(t.offset, io.SeekStart); err != nil {
		slog.Debug("zeek: seek notice log failed", "path", t.path, "err", err)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		slog.Debug("zeek: read notice log failed", "path", t.path, "err", err)
		return
	}

	// Zeek may still be writing the last line. Stop at the last newline; the unfinished
	// line is read again, whole, on a later poll.
	end := bytes.LastIndexByte(data, '\n')
	if end == -1 {
		return
	}

	t.offset += int64(end + 1)

	for _, line := range strings.Split(string(data[:end]), "\n") {
		event, ok, err := t.parser.parseLine(line)
		if err != nil {
			// Warn once: a format mismatch fails every line, and one warning is enough
			// to show that alerts are being missed.
			if !t.warnedBadLine {
				slog.Warn("zeek: notice log line could not be parsed; DNS-bypass alerts may be missed", "path", t.path, "err", err)
				t.warnedBadLine = true
			} else {
				slog.Debug("zeek: notice log line could not be parsed", "path", t.path, "err", err)
			}

			continue
		}

		if !ok || events == nil {
			continue
		}

		select {
		case events <- event:
		default:
			slog.Warn("zeek: DNS-bypass alert dropped, alert handler is behind", "sni", event.SNI, "dst_ip", event.DstIP)
		}
	}
}

// reportOpenError logs why notice.log can't be read, once per change of reason, so a
// 2-second poll doesn't repeat it.
func (t *noticeTailer) reportOpenError(err error) {
	if errors.Is(err, fs.ErrNotExist) {
		if t.state != fileMissing {
			slog.Info("zeek: waiting for notice log; Zeek creates it at its first alert", "path", t.path)
			t.state = fileMissing
		}
		// Whatever appears at this path next is a new file: read it from the start.
		t.offset = 0
		t.parser = noticeParser{}

		return
	}

	if t.state != fileUnreadable {
		slog.Warn("zeek: cannot open notice log; DNS-bypass alerts are not being read", "path", t.path, "err", err)
		t.state = fileUnreadable
	}
}

// WatchNoticeLog tails a Zeek notice log and emits parsed DNS-bypass Events.
func WatchNoticeLog(ctx context.Context, path string, events chan<- Event) error {
	logPath := strings.TrimSpace(path)
	if ctx == nil || logPath == "" {
		return nil
	}

	tailer := &noticeTailer{path: logPath}
	tailer.skipExisting()

	poller := time.NewTicker(2 * time.Second)
	defer poller.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poller.C:
			tailer.poll(events)
		}
	}
}
