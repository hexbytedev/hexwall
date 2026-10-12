package zeek

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The testdata notice logs are real Zeek 9.0.0 output: this package's dns-bypass.zeek run
// over Zeek's own chrome-34-google.pcap, once with default settings (TSV) and once with
// LogAscii::use_json=T. Regenerate them whenever the script changes:
//
//	zeek -C -r /opt/zeek/share/btest/data/pcaps/tls/chrome-34-google.pcap dns-bypass.zeek [LogAscii::use_json=T]

func readFixtureLines(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func parseAll(t *testing.T, lines []string) []Event {
	t.Helper()
	var parser noticeParser
	var events []Event
	for _, line := range lines {
		event, ok, err := parser.parseLine(line)
		if err != nil {
			t.Fatalf("parseLine(%q) error = %v", line, err)
		}
		if ok {
			events = append(events, event)
		}
	}
	return events
}

func assertGoogleBypassEvent(t *testing.T, events []Event) {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	event := events[0]

	if event.SNI != "google.de" {
		t.Errorf("SNI = %q, want %q", event.SNI, "google.de")
	}
	if event.SrcIP != "192.168.4.149" {
		t.Errorf("SrcIP = %q, want %q", event.SrcIP, "192.168.4.149")
	}
	if event.SrcPort != "55881" {
		t.Errorf("SrcPort = %q, want %q", event.SrcPort, "55881")
	}
	if event.DstIP != "74.125.239.152" {
		t.Errorf("DstIP = %q, want %q", event.DstIP, "74.125.239.152")
	}
	if event.DstPort != "443" {
		t.Errorf("DstPort = %q, want %q", event.DstPort, "443")
	}
	want := time.Unix(1398362902, 726337000)
	if diff := event.Timestamp.Sub(want); diff < -time.Microsecond || diff > time.Microsecond {
		t.Errorf("Timestamp = %v, want %v (Zeek's ts, not the parse time)", event.Timestamp, want)
	}
}

func TestNoticeParser_RealTSV(t *testing.T) {
	assertGoogleBypassEvent(t, parseAll(t, readFixtureLines(t, "notice.tsv")))
}

func TestNoticeParser_RealJSON(t *testing.T) {
	assertGoogleBypassEvent(t, parseAll(t, readFixtureLines(t, "notice.ndjson")))
}

func TestNoticeParser_TSVLineBeforeHeader(t *testing.T) {
	var dataLine string
	for _, line := range readFixtureLines(t, "notice.tsv") {
		if !strings.HasPrefix(line, "#") {
			dataLine = line
		}
	}

	var parser noticeParser
	if _, _, err := parser.parseLine(dataLine); !errors.Is(err, ErrNoticeHeaderMissing) {
		t.Fatalf("parseLine() error = %v, want ErrNoticeHeaderMissing", err)
	}
}

func TestNoticeParser_IgnoresOtherNoticeTypes(t *testing.T) {
	line := readFixtureLines(t, "notice.ndjson")[0]
	line = strings.Replace(line, bypassNote, "SSL::Invalid_Server_Cert", 1)

	var parser noticeParser
	_, ok, err := parser.parseLine(line)
	if err != nil || ok {
		t.Fatalf("parseLine() = ok %v, err %v; want a silent skip", ok, err)
	}
}

// A notice from an older copy of the script (SNI only in msg, no sub) must fail loudly,
// not be skipped: the warning tells the user to re-run zeek-setup.
func TestNoticeParser_BypassWithoutSub(t *testing.T) {
	line := readFixtureLines(t, "notice.ndjson")[0]
	line = strings.Replace(line, `"sub":"google.de",`, "", 1)

	var parser noticeParser
	if _, _, err := parser.parseLine(line); !errors.Is(err, ErrNoticeNoSNI) {
		t.Fatalf("parseLine() error = %v, want ErrNoticeNoSNI", err)
	}
}

func TestNoticeParser_InvalidJSON(t *testing.T) {
	var parser noticeParser
	if _, _, err := parser.parseLine(`{"note":`); err == nil {
		t.Fatal("parseLine() error = nil, want error")
	}
}

// Zeek can be mid-write when hexwall polls. A half-written line must not be parsed (its
// SNI would be cut short); it must be read whole on the next poll.
func TestNoticeTailer_WaitsForCompleteLine(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "notice.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	cut := strings.Index(string(data), "google.de") + len("goo")

	path := filepath.Join(t.TempDir(), "notice.log")
	if err := os.WriteFile(path, data[:cut], 0o600); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 10)
	tailer := &noticeTailer{path: path}

	tailer.poll(events)
	if len(events) != 0 {
		t.Fatalf("got %d events from a half-written line, want 0", len(events))
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tailer.poll(events)

	close(events)
	var got []Event
	for event := range events {
		got = append(got, event)
	}
	assertGoogleBypassEvent(t, got)
}

func TestNoticeTailer_RelearnsHeaderAfterRotation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "notice.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notice.log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 10)
	tailer := &noticeTailer{path: path}
	tailer.poll(events)
	<-events

	// Rotation: a fresh, smaller file with its own header.
	var header strings.Builder
	var dataLine string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#fields") || strings.HasPrefix(line, "#separator") {
			header.WriteString(line + "\n")
		} else if line != "" && !strings.HasPrefix(line, "#") {
			dataLine = line
		}
	}
	if err := os.WriteFile(path, []byte(header.String()+dataLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer.poll(events)

	if len(events) != 1 {
		t.Fatalf("got %d events after rotation, want 1", len(events))
	}
}

// Alerts already in notice.log when hexwall starts must not be replayed: in enforce mode
// each one would trigger a kill attempt on every restart. Alerts written afterwards must
// still be read, which needs the header learned during the skip.
func TestNoticeTailer_SkipsExistingAlerts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "notice.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notice.log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 10)
	tailer := &noticeTailer{path: path}
	tailer.skipExisting()
	tailer.poll(events)
	if len(events) != 0 {
		t.Fatalf("got %d replayed events, want 0", len(events))
	}

	var dataLine string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			dataLine = line
		}
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(dataLine + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	tailer.poll(events)
	if len(events) != 1 {
		t.Fatalf("got %d events for a new alert, want 1", len(events))
	}
}

func TestDNSBypassScriptEmbedded(t *testing.T) {
	if !strings.Contains(string(DNSBypassScript), "$sub=sni") {
		t.Fatal("embedded script does not write the SNI to sub, which parseLine reads")
	}
}

// The tailer polls every 2 s. A missing notice.log is normal until Zeek's first alert, so
// "waiting" must be logged once, not on every poll, and the file appearing must be logged.
// Not parallel: it swaps the default logger.
func TestNoticeTailer_LogsFileStateOnce(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	path := filepath.Join(t.TempDir(), "notice.log")
	tailer := &noticeTailer{path: path}
	events := make(chan Event, 10)

	tailer.skipExisting()
	for range 5 {
		tailer.poll(events)
	}
	if got := strings.Count(logs.String(), "waiting for notice log"); got != 1 {
		t.Fatalf("logged 'waiting' %d times over 6 polls, want 1:\n%s", got, logs.String())
	}

	data, err := os.ReadFile(filepath.Join("testdata", "notice.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		tailer.poll(events)
	}
	if got := strings.Count(logs.String(), "notice log found"); got != 1 {
		t.Fatalf("logged 'found' %d times, want 1:\n%s", got, logs.String())
	}
	// Everything in a file that appears after startup is new, so its alert is delivered.
	if len(events) != 1 {
		t.Fatalf("got %d events from the newly created file, want 1", len(events))
	}
}
