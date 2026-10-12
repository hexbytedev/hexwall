package pihole

import "testing"

// Expected results below were confirmed against Pi-hole's own engine
// (pihole-FTL v6.7.1 regex-test), not assumed.

func newRegexTestChecker(t *testing.T, rules map[string]int) *Checker {
	t.Helper()

	gravDB, gravPath := openTestGravityDB(t)
	for rule, listType := range rules {
		insertDomain(t, gravDB, rule, listType)
	}

	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	t.Cleanup(func() { _ = checker.Close() })

	if err := checker.RefreshRegexLists(); err != nil {
		t.Fatalf("RefreshRegexLists() error = %v", err)
	}

	return checker
}

func TestIsBlockedByPolicy_RegexDenylist(t *testing.T) {
	t.Parallel()
	checker := newRegexTestChecker(t, map[string]int{
		`(^|\.)tracker\.example$`:                  3, // type 3 = regex denylist
		`^ad[[:digit:]]+\.`:                        3,
		`(^|\.)Shouty\.Example$`:                   3,
		`(^|\.)aaaa-only\.example$;querytype=AAAA`: 3,
		`(^|\.)reply\.example$;reply=nxdomain`:     3,
		`(a)\1`:                                    3, // backreference: valid for FTL, not for Go's regexp
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"c2.tracker.example", true},
		{"tracker.example", true},
		{"tracker.example.evil.com", false}, // the $ anchor holds
		{"C2.TRACKER.EXAMPLE", true},        // FTL matches case-insensitively
		{"ad7.example", true},               // POSIX character class
		{"api.shouty.example", true},        // uppercase pattern, lowercase domain
		{"x.reply.example", true},           // reply= changes the answer, not the verdict
		{"x.aaaa-only.example", false},      // a querytype-limited deny rule is skipped
		{"unrelated.example", false},
	}
	for _, tt := range tests {
		blocked, err := checker.IsBlockedByPolicy(tt.domain)
		if err != nil {
			t.Fatalf("IsBlockedByPolicy(%q) error = %v", tt.domain, err)
		}

		if blocked != tt.want {
			t.Errorf("IsBlockedByPolicy(%q) = %v, want %v", tt.domain, blocked, tt.want)
		}
	}
}

func TestIsAllowedByPolicy_RegexAllowlist(t *testing.T) {
	t.Parallel()
	checker := newRegexTestChecker(t, map[string]int{
		`(^|\.)mycompany\.com$`:                   2, // type 2 = regex allowlist
		`(^|\.)ipv6-app\.example$;querytype=AAAA`: 2,
	})

	tests := []struct {
		domain string
		want   bool
	}{
		{"api.mycompany.com", true},
		{"mycompany.com.evil.net", false},
		{"x.ipv6-app.example", true}, // a querytype-limited allow rule is applied anyway
		{"unrelated.example", false},
	}
	for _, tt := range tests {
		allowed, err := checker.IsAllowedByPolicy(tt.domain)
		if err != nil {
			t.Fatalf("IsAllowedByPolicy(%q) error = %v", tt.domain, err)
		}

		if allowed != tt.want {
			t.Errorf("IsAllowedByPolicy(%q) = %v, want %v", tt.domain, allowed, tt.want)
		}
	}
}

func TestRegexRule_Invert(t *testing.T) {
	t.Parallel()

	rule, err := parseRegexRule(`(^|\.)tracker\.example$;invert`, false)
	if err != nil {
		t.Fatalf("parseRegexRule() error = %v", err)
	}

	if !rule.matches("good.example") {
		t.Error("inverted rule should match a domain the pattern does not")
	}

	if rule.matches("c2.tracker.example") {
		t.Error("inverted rule should not match a domain the pattern does")
	}
}

func TestParseRegexRule_UnknownOption(t *testing.T) {
	t.Parallel()

	if _, err := parseRegexRule(`^x\.;future=1`, false); err == nil {
		t.Error("deny rule with an unknown option should be skipped")
	}

	if _, err := parseRegexRule(`^x\.;future=1`, true); err != nil {
		t.Errorf("allow rule with an unknown option should still apply, got %v", err)
	}
}

func TestRefreshRegexLists_PicksUpNewRules(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	t.Cleanup(func() { _ = gravDB.Close() })

	checker := newTestChecker(t, gravPath)
	t.Cleanup(func() { _ = checker.Close() })

	if err := checker.RefreshRegexLists(); err != nil {
		t.Fatalf("RefreshRegexLists() error = %v", err)
	}

	if blocked, _ := checker.IsBlockedByPolicy("c2.tracker.example"); blocked {
		t.Fatal("blocked before any rule exists")
	}

	insertDomain(t, gravDB, `(^|\.)tracker\.example$`, 3)

	if err := checker.RefreshRegexLists(); err != nil {
		t.Fatalf("RefreshRegexLists() error = %v", err)
	}

	if blocked, _ := checker.IsBlockedByPolicy("c2.tracker.example"); !blocked {
		t.Fatal("rule added in Pi-hole not picked up by refresh")
	}
}

func TestRefreshRegexLists_NilGravityDB(t *testing.T) {
	t.Parallel()

	checker := &Checker{}
	if err := checker.RefreshRegexLists(); err != nil {
		t.Fatalf("RefreshRegexLists() error = %v", err)
	}

	if checker.matchesRegex("anything.example", false) {
		t.Fatal("no rules loaded, nothing should match")
	}
}
