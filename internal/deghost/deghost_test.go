package deghost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckDomainOK(t *testing.T) {
	t.Parallel()

	want := DomainReport{
		Status:          "allowed",
		HasMX:           true,
		Disposable:      false,
		Spam:            false,
		PublicDomain:    true,
		RelayDomain:     false,
		Blacklisted:     false,
		DomainAgeInDays: 11117,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}

		if r.URL.Path != "/domain/example.com" {
			t.Errorf("path = %s, want /domain/example.com", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CheckDomain() error = %v", err)
	}

	if got == nil {
		t.Fatal("CheckDomain() = nil, want report")
	}

	if got.Status != want.Status {
		t.Errorf("Status = %q, want %q", got.Status, want.Status)
	}

	if got.HasMX != want.HasMX {
		t.Errorf("HasMX = %v, want %v", got.HasMX, want.HasMX)
	}

	if got.DomainAgeInDays != want.DomainAgeInDays {
		t.Errorf("DomainAgeInDays = %d, want %d", got.DomainAgeInDays, want.DomainAgeInDays)
	}
}

func TestCheckDomainStatusForbiddenDecodesBody(t *testing.T) {
	t.Parallel()

	want := DomainReport{
		Status:          "not_allowed",
		HasMX:           false,
		Disposable:      false,
		Spam:            false,
		PublicDomain:    false,
		RelayDomain:     false,
		Blacklisted:     false,
		DomainAgeInDays: 0,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "blocked.example.com")
	if err != nil {
		t.Fatalf("CheckDomain() on 403 error = %v", err)
	}

	if got == nil {
		t.Fatal("CheckDomain() on 403 = nil, want decoded report (not nil like IP endpoint)")
	}

	if got.Status != "not_allowed" {
		t.Errorf("Status = %q, want %q", got.Status, "not_allowed")
	}
}

func TestCheckDomainStatusBadRequestDecodesBody(t *testing.T) {
	t.Parallel()

	want := DomainReport{
		Status:          "not_allowed",
		HasMX:           false,
		Blacklisted:     true,
		DomainAgeInDays: 0,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "bad.example.com")
	if err != nil {
		t.Fatalf("CheckDomain() on 400 error = %v", err)
	}

	if got == nil {
		t.Fatal("CheckDomain() on 400 = nil, want decoded report")
	}

	if !got.Blacklisted {
		t.Error("Blacklisted = false, want true")
	}
}

func TestCheckDomainStatusInternalServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on 500 = %v, want error", got)
	}
}

func TestCheckDomainStatusGatewayTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on 504 = %v, want error", got)
	}
}

func TestCheckDomainStatusClientClosedRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(499)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on 499 = %v, want error", got)
	}
}

func TestCheckDomainMalformedJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := fmt.Fprint(w, `{"status": "allowed" bad json`); err != nil {
			t.Errorf("fmt.Fprint: %v", err)
		}
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on bad JSON = %v, want error", got)
	}
}

func TestCheckDomainNilClient(t *testing.T) {
	t.Parallel()

	var c *Client

	got, err := c.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on nil client = %v, want error", got)
	}
}

func TestCheckDomainEmptyBaseURL(t *testing.T) {
	t.Parallel()

	client := &Client{baseURL: "", httpClient: &http.Client{}}

	got, err := client.CheckDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("CheckDomain() on empty baseURL = %v, want error", got)
	}
}

func TestCheckDomainEmptyDomain(t *testing.T) {
	t.Parallel()

	client := NewClient("https://example.com", 5)

	got, err := client.CheckDomain(context.Background(), "  ")
	if err == nil {
		t.Fatalf("CheckDomain() on empty domain = %v, want error", got)
	}
}

func TestCheckDomainNormalized(t *testing.T) {
	t.Parallel()

	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DomainReport{Status: "allowed"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, srv.Client().Timeout)

	_, err := client.CheckDomain(context.Background(), "  Example.COM  ")
	if err != nil {
		t.Fatalf("CheckDomain() error = %v", err)
	}

	want := "/domain/example.com"
	if gotPath != want {
		t.Errorf("request path = %q, want %q (domain should be trimmed and lowercased)", gotPath, want)
	}
}

func TestShouldBlockDomainNilReport(t *testing.T) {
	t.Parallel()

	if ShouldBlockDomain(nil) {
		t.Error("ShouldBlockDomain(nil) = true, want false")
	}
}

func TestShouldBlockDomainNotAllowed(t *testing.T) {
	t.Parallel()

	report := &DomainReport{Status: "not_allowed"}
	if !ShouldBlockDomain(report) {
		t.Error("ShouldBlockDomain(not_allowed) = false, want true")
	}
}

func TestShouldBlockDomainBlacklisted(t *testing.T) {
	t.Parallel()

	report := &DomainReport{Status: "allowed", Blacklisted: true}
	if !ShouldBlockDomain(report) {
		t.Error("ShouldBlockDomain(blacklisted) = false, want true")
	}
}

func TestShouldBlockDomainBothFalse(t *testing.T) {
	t.Parallel()

	report := &DomainReport{Status: "allowed", Blacklisted: false}
	if ShouldBlockDomain(report) {
		t.Error("ShouldBlockDomain(allowed, not blacklisted) = true, want false")
	}
}

func TestShouldBlockDomainDisposableAloneDoesNotBlock(t *testing.T) {
	t.Parallel()

	report := &DomainReport{Status: "allowed", Disposable: true}
	if ShouldBlockDomain(report) {
		t.Error("ShouldBlockDomain(disposable alone) = true, want false")
	}
}

func TestShouldBlockDomainSpamAloneDoesNotBlock(t *testing.T) {
	t.Parallel()

	report := &DomainReport{Status: "allowed", Spam: true}
	if ShouldBlockDomain(report) {
		t.Error("ShouldBlockDomain(spam alone) = true, want false")
	}
}

func TestCheckIPOK(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9","security":{"is_attacker":true}}`))
	}))
	t.Cleanup(srv.Close)

	report, err := NewClient(srv.URL, time.Second).CheckIP(context.Background(), " 203.0.113.9 ")
	if err != nil {
		t.Fatalf("CheckIP() error = %v", err)
	}

	if gotPath != "/ip/203.0.113.9" {
		t.Fatalf("request path = %q, want /ip/203.0.113.9", gotPath)
	}

	if report == nil || !report.Security.IsAttacker {
		t.Fatalf("CheckIP() report = %+v, want is_attacker decoded", report)
	}
}

// The API answers 403 for private and reserved IPs; that is a clean verdict, not an error.
func TestCheckIPForbiddenIsCleanNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	report, err := NewClient(srv.URL, time.Second).CheckIP(context.Background(), "10.0.0.1")
	if err != nil || report != nil {
		t.Fatalf("CheckIP() = %+v, %v; want nil, nil", report, err)
	}
}

// Any other failure is an error, never a verdict: a failed lookup must not become a kill.
func TestCheckIPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ip/203.0.113.1" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(`{not json`))
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, time.Second)

	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "not-an-ip", ""} {
		if report, err := client.CheckIP(context.Background(), ip); err == nil || report != nil {
			t.Errorf("CheckIP(%q) = %+v, %v; want nil report and an error", ip, report, err)
		}
	}

	var nilClient *Client
	if _, err := nilClient.CheckIP(context.Background(), "203.0.113.1"); err == nil {
		t.Error("nil client CheckIP() error = nil, want error")
	}
}

func TestShouldKill(t *testing.T) {
	tests := []struct {
		name     string
		security SecurityReport
		want     bool
	}{
		{"abuser", SecurityReport{IsAbuser: true}, true},
		{"attacker", SecurityReport{IsAttacker: true}, true},
		{"threat", SecurityReport{IsThreat: true}, true},
		// Anonymity alone is too noisy to kill on: VPN, Tor and cloud users are not attackers.
		{"vpn, tor, proxy, cloud", SecurityReport{IsVPN: true, IsTor: true, IsProxy: true, IsCloudProvider: true}, false},
		{"clean", SecurityReport{}, false},
	}
	for _, tt := range tests {
		if got := ShouldKill(&IPReport{Security: tt.security}); got != tt.want {
			t.Errorf("ShouldKill(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}

	if ShouldKill(nil) {
		t.Error("ShouldKill(nil) = true, want false")
	}
}
