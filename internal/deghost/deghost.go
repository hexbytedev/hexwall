// Package deghost wraps the external fraud API used for IP reputation checks.
// It converts remote responses into local kill-policy decisions.
package deghost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client calls the external fraud API used for IP reputation checks.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// IPReport matches the API payload for IP fraud checks.
type IPReport struct {
	IP       string         `json:"ip"`
	Security SecurityReport `json:"security"`
}

// SecurityReport describes fraud and anonymity signals for an IP.
type SecurityReport struct {
	IsAbuser        bool `json:"is_abuser"`
	IsAttacker      bool `json:"is_attacker"`
	IsBogon         bool `json:"is_bogon"`
	IsCloudProvider bool `json:"is_cloud_provider"`
	IsProxy         bool `json:"is_proxy"`
	IsRelay         bool `json:"is_relay"`
	IsTor           bool `json:"is_tor"`
	IsTorExit       bool `json:"is_tor_exit"`
	IsVPN           bool `json:"is_vpn"`
	IsAnonymous     bool `json:"is_anonymous"`
	IsThreat        bool `json:"is_threat"`
}

// NewClient creates a Client for the given API base URL.
func NewClient(baseURL string, timeout time.Duration) *Client {
	trimmed := strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: trimmed,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// CheckIP fetches a fraud report for a single IP.
// It returns a nil report and nil error for HTTP 403 responses, which the API uses for private or reserved IPs.
func (c *Client) CheckIP(ctx context.Context, ip string) (*IPReport, error) {
	if c == nil {
		return nil, errors.New("nil deghost client")
	}

	if strings.TrimSpace(ip) == "" {
		return nil, errors.New("ip is required")
	}

	url := c.baseURL + "/ip/" + ip
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deghost returned status %d", resp.StatusCode)
	}

	var report IPReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &report, nil
}

// ShouldKill reports whether the report matches the current kill policy.
func ShouldKill(report *IPReport) bool {
	if report == nil {
		return false
	}

	return report.Security.IsAbuser || report.Security.IsAttacker || report.Security.IsThreat
}
