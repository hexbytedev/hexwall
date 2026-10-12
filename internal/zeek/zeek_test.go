package zeek

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at path without starting the
// background tailLoop goroutine, so tests can call processNewLines directly
// at controlled points instead of racing a real ticker.
func newTestClient(t *testing.T, path string) *Client {
	t.Helper()
	return &Client{
		logPath: path,
		cache:   make(map[string]sniEntry),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestClientProcessNewLines_BasicParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	domain, ok := c.Lookup("51820", "203.0.113.20", "443")
	if !ok {
		t.Fatal("Lookup() ok = false, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() domain = %q, want %q", domain, "example.com")
	}

	// The reverse orientation must also resolve, since Lookup doesn't know
	// in advance which side of the connection is the local endpoint.
	domain, ok = c.Lookup("443", "10.0.0.5", "51820")
	if !ok {
		t.Fatal("Lookup() reverse orientation ok = false, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() reverse orientation domain = %q, want %q", domain, "example.com")
	}
}

func TestClientProcessNewLines_SkipsIncompleteRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443}`+"\n"+
		`not json at all`+"\n"+
		`{"id.orig_h":"","id.orig_p":1,"id.resp_h":"203.0.113.21","id.resp_p":443,"server_name":"missing-orig-host.example"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	if len(c.cache) != 0 {
		t.Fatalf("cache = %v, want empty (no valid records in input)", c.cache)
	}
}

func TestClientProcessNewLines_PartialLineHeldAcrossTicks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	full := `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}` + "\n"

	// Simulate Zeek flushing mid-record: only the first half of the line
	// lands before the poll fires.
	split := len(full) / 2
	writeFile(t, path, full[:split])

	c := newTestClient(t, path)
	c.processNewLines()

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); ok {
		t.Fatal("Lookup() found a record from a partial line, want none yet")
	}
	if len(c.pending) == 0 {
		t.Fatal("pending is empty, want the partial line to be held over")
	}

	// The rest of the line arrives on the next tick.
	writeFile(t, path, full)
	c.processNewLines()

	domain, ok := c.Lookup("51820", "203.0.113.20", "443")
	if !ok {
		t.Fatal("Lookup() ok = false after completing the line, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() domain = %q, want %q", domain, "example.com")
	}
}

func TestClientProcessNewLines_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); !ok {
		t.Fatal("Lookup() ok = false before rotation, want true")
	}

	// Rotation: zeekctl closes the current log and starts a fresh, empty
	// file at the same path — simulate the two ticks that straddle that.
	writeFile(t, path, "")
	c.processNewLines()
	writeFile(t, path, `{"id.orig_h":"10.0.0.9","id.orig_p":9000,"id.resp_h":"203.0.113.30","id.resp_p":443,"server_name":"post-rotation.example"}`+"\n")
	c.processNewLines()

	if domain, ok := c.Lookup("9000", "203.0.113.30", "443"); !ok || domain != "post-rotation.example" {
		t.Fatalf("Lookup() after rotation = (%q, %v), want (%q, true)", domain, ok, "post-rotation.example")
	}
}

func TestClientLookup_Expiry(t *testing.T) {
	c := newTestClient(t, "")
	c.cache["51820|203.0.113.20|443"] = sniEntry{
		domain:     "example.com",
		observedAt: time.Now().Add(-entryExpiry - time.Second),
	}

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); ok {
		t.Fatal("Lookup() ok = true for an expired entry, want false")
	}
}

// ---- TSV format (Zeek's actual default output) --------------------------

// realZeekTSVHeader and realZeekTSVDataLine are captured verbatim from a
// live Zeek 9.0.0 instance's ssl.log (default config, no LogAscii::use_json).
// This is the format a stock Zeek install actually produces — the JSON
// tests above only exercise the opt-in LogAscii::use_json = T path.
const realZeekTSVHeader = "#separator \\x09\n" +
	"#set_separator\t,\n" +
	"#empty_field\t(empty)\n" +
	"#unset_field\t-\n" +
	"#path\tssl\n" +
	"#open\t2026-09-23-16-59-25\n" +
	"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished\tssl_history\tcert_chain_fps\tclient_cert_chain_fps\tsni_matches_cert\n" +
	"#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tstring\tstring\tbool\tstring\tvector[string]\tvector[string]\tbool\n"

const realZeekTSVDataLine = "1790163565.389393\tC5MrwN15Qi19OF5Y2g\t192.168.0.223\t37526\t172.66.147.243\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tx25519\texample.com\tF\t-\t-\tT\tCsiI\t-\t-\t-\n"

func TestParseTSVFieldsLine(t *testing.T) {
	t.Parallel()

	lines := strings.Split(strings.TrimRight(realZeekTSVHeader, "\n"), "\n")
	var fieldsLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "#fields\t") {
			fieldsLine = l
		}
	}
	if fieldsLine == "" {
		t.Fatal("test fixture has no #fields line")
	}

	fields := parseTSVFieldsLine(fieldsLine)
	want := map[string]int{
		"ts": 0, "uid": 1, "id.orig_h": 2, "id.orig_p": 3, "id.resp_h": 4, "id.resp_p": 5,
		"server_name": 9,
	}
	for name, idx := range want {
		if fields[name] != idx {
			t.Errorf("parseTSVFieldsLine()[%q] = %d, want %d", name, fields[name], idx)
		}
	}

	if parseTSVFieldsLine("#types\ttime\tstring") != nil {
		t.Error("parseTSVFieldsLine(#types line) = non-nil, want nil (only #fields should match)")
	}
}

func TestReadTSVHeader(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, realZeekTSVHeader+realZeekTSVDataLine)

	fields := readTSVHeader(path)
	if fields == nil {
		t.Fatal("readTSVHeader() = nil, want a field map for a real TSV file")
	}
	if fields["server_name"] != 9 {
		t.Fatalf("readTSVHeader()[server_name] = %d, want 9", fields["server_name"])
	}
}

func TestReadTSVHeaderNilForJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}`+"\n")

	if fields := readTSVHeader(path); fields != nil {
		t.Fatalf("readTSVHeader() on a JSON file = %v, want nil", fields)
	}
}

// newTestClientTSV builds a Client the way NewClient would for a TSV file:
// with tsvFields pre-populated from the file's own header, since the real
// tailer always starts reading from the file's current end (past the
// header) and depends on this separate, from-the-start read to learn the
// column order at all.
func newTestClientTSV(t *testing.T, path string) *Client {
	t.Helper()
	return &Client{
		logPath:   path,
		cache:     make(map[string]sniEntry),
		tsvFields: readTSVHeader(path),
	}
}

func TestClientProcessNewLines_TSVRealFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, realZeekTSVHeader+realZeekTSVDataLine)

	c := newTestClientTSV(t, path)
	c.processNewLines()

	domain, ok := c.Lookup("37526", "172.66.147.243", "443")
	if !ok {
		t.Fatal("Lookup() ok = false, want true for the real captured TSV line")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() domain = %q, want %q", domain, "example.com")
	}

	// Reverse orientation too.
	if domain, ok := c.Lookup("443", "192.168.0.223", "37526"); !ok || domain != "example.com" {
		t.Fatalf("Lookup() reverse orientation = (%q, %v), want (%q, true)", domain, ok, "example.com")
	}
}

func TestClientProcessNewLines_TSVUnsetServerNameSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	// server_name column (index 9) is "-": Zeek's unset-field marker, e.g. a
	// resumed session where the name wasn't re-sent.
	line := "1790163565.389393\tCabc\t192.168.0.223\t40000\t172.66.147.243\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tx25519\t-\tT\t-\t-\tT\tCsiI\t-\t-\t-\n"
	writeFile(t, path, realZeekTSVHeader+line)

	c := newTestClientTSV(t, path)
	c.processNewLines()

	if len(c.cache) != 0 {
		t.Fatalf("cache = %v, want empty (unset server_name must be skipped)", c.cache)
	}
}

func TestClientProcessNewLines_TSVShortLineSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	// Far fewer columns than the header declares — must not panic (index
	// out of range) and must not produce a cache entry.
	writeFile(t, path, realZeekTSVHeader+"1790163565.389393\tCabc\t192.168.0.223\n")

	c := newTestClientTSV(t, path)
	c.processNewLines()

	if len(c.cache) != 0 {
		t.Fatalf("cache = %v, want empty for a too-short TSV line", c.cache)
	}
}

func TestClientProcessNewLines_TSVDataBeforeHeaderSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, realZeekTSVDataLine) // no header at all

	// Deliberately NOT using newTestClientTSV: this simulates tsvFields
	// never having been learned (e.g. the header lived entirely before this
	// client's starting offset in some edge case).
	c := newTestClient(t, path)
	c.processNewLines()

	if len(c.cache) != 0 {
		t.Fatalf("cache = %v, want empty when no #fields header has been seen", c.cache)
	}
}

func TestClientProcessNewLines_TSVRotationRelearnsHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, realZeekTSVHeader+realZeekTSVDataLine)

	c := newTestClientTSV(t, path)
	c.processNewLines()
	if _, ok := c.Lookup("37526", "172.66.147.243", "443"); !ok {
		t.Fatal("Lookup() ok = false before rotation, want true")
	}

	// Rotation: a fresh, smaller file appears at the same path, with its own
	// header re-written from scratch (a real Zeek restart does exactly this).
	newHeader := "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\n"
	newLine := "1790163999.0\tCnew\t10.0.0.5\t51820\t203.0.113.30\t443\tpost-rotation.example\n"
	writeFile(t, path, "") // straddling tick, matches the JSON rotation test above
	c.processNewLines()
	writeFile(t, path, newHeader+newLine)
	c.processNewLines()

	domain, ok := c.Lookup("51820", "203.0.113.30", "443")
	if !ok || domain != "post-rotation.example" {
		t.Fatalf("Lookup() after rotation = (%q, %v), want (%q, true)", domain, ok, "post-rotation.example")
	}
}

// A nil *Client can sit inside the scanner's SNISource interface; it must answer
// "no SNI", not panic.
func TestNilClientLookup(t *testing.T) {
	var c *Client
	if sni, ok := c.Lookup("40000", "203.0.113.1", "443"); ok || sni != "" {
		t.Fatalf("nil Client.Lookup() = %q, %v; want \"\", false", sni, ok)
	}
}
