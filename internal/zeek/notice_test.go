package zeek

import (
	"testing"
	"time"
)

func TestParseNoticeLine(t *testing.T) {
	line := `{"note":"DNSBypass::PossibleBypass","src_ip":"192.0.2.10","dst_ip":"203.0.113.20","dst_port":"443","sni":"evil.example","msg":"SNI evil.example from 192.0.2.10"}`

	event, err := ParseNoticeLine(line)
	if err != nil {
		t.Fatalf("ParseNoticeLine() error = %v", err)
	}

	if event.SrcIP != "192.0.2.10" {
		t.Fatalf("ParseNoticeLine().SrcIP = %q, want %q", event.SrcIP, "192.0.2.10")
	}
	if event.DstIP != "203.0.113.20" {
		t.Fatalf("ParseNoticeLine().DstIP = %q, want %q", event.DstIP, "203.0.113.20")
	}
	if event.DstPort != "443" {
		t.Fatalf("ParseNoticeLine().DstPort = %q, want %q", event.DstPort, "443")
	}
	if event.SNI != "evil.example" {
		t.Fatalf("ParseNoticeLine().SNI = %q, want %q", event.SNI, "evil.example")
	}
	if event.Timestamp.IsZero() {
		t.Fatal("ParseNoticeLine().Timestamp = zero time, want non-zero")
	}
	if event.Timestamp.After(time.Now().Add(time.Second)) {
		t.Fatalf("ParseNoticeLine().Timestamp too far in the future: %v", event.Timestamp)
	}
}

func TestParseNoticeLineRejectsInvalidJSON(t *testing.T) {
	_, err := ParseNoticeLine(`{"note":`)
	if err == nil {
		t.Fatal("ParseNoticeLine() error = nil, want error")
	}
}
