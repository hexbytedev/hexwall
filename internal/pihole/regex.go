package pihole

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
)

// Pi-hole's regex lists hold rules, not names: one pattern such as (^|\.)tracker\.example$
// covers every subdomain. FTL matches them as case-insensitive POSIX extended regex; Go's
// regexp accepts nearly all of that syntax, and a pattern it cannot compile is skipped with
// a warning.
//
// A pattern can carry FTL options after a semicolon (";invert", ";querytype=AAAA",
// ";reply=..."). hexwall judges a TLS connection, not a DNS query, so an option it cannot
// honour exactly is resolved toward not killing: an allow rule is applied anyway (too broad
// an allow can only miss a block), while a deny rule is skipped (too broad a deny would kill
// traffic Pi-hole itself lets through).

const (
	regexAllowView = "vw_regex_allowlist"
	regexDenyView  = "vw_regex_denylist"
)

// regexRule is one compiled Pi-hole regex list entry.
type regexRule struct {
	re     *regexp.Regexp
	invert bool
}

func (r regexRule) matches(domain string) bool {
	return r.re.MatchString(domain) != r.invert
}

// regexLists is an immutable snapshot of both regex lists. The raw patterns are kept so a
// refresh can tell whether anything changed, and skip recompiling (and re-warning) if not.
type regexLists struct {
	allowRaw []string
	denyRaw  []string
	allow    []regexRule
	deny     []regexRule
}

// parseRegexRule compiles one regex list entry. It returns an error when the entry must be
// skipped: the pattern does not compile, or it is a deny rule with an option hexwall cannot
// honour for a connection.
func parseRegexRule(raw string, allow bool) (regexRule, error) {
	pattern, options, _ := strings.Cut(raw, ";")

	var rule regexRule

	if options != "" {
		for _, option := range strings.Split(options, ";") {
			switch {
			case option == "invert":
				rule.invert = true
			case strings.HasPrefix(option, "reply="):
				// Changes how Pi-hole answers a blocked query, not whether it blocks.
			case strings.HasPrefix(option, "querytype="):
				if !allow {
					return regexRule{}, errors.New("deny rule limited to a DNS query type cannot be applied to a connection")
				}
			default:
				if !allow {
					return regexRule{}, fmt.Errorf("unknown option %q", option)
				}
			}
		}
	}

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return regexRule{}, fmt.Errorf("pattern does not compile in Go: %w", err)
	}

	rule.re = re

	return rule, nil
}

func compileRegexRules(raws []string, allow bool) []regexRule {
	rules := make([]regexRule, 0, len(raws))
	for _, raw := range raws {
		rule, err := parseRegexRule(raw, allow)
		if err != nil {
			if allow {
				slog.Warn("pi-hole regex allow rule skipped; connections it allows may still be killed by reputation checks",
					"rule", raw, "err", err)
			} else {
				slog.Warn("pi-hole regex deny rule skipped", "rule", raw, "err", err)
			}

			continue
		}

		rules = append(rules, rule)
	}

	return rules
}

// RefreshRegexLists reloads Pi-hole's regex allow and deny lists from gravity.db, so rules
// edited in Pi-hole take effect without restarting hexwall. On error the previously loaded
// rules stay in use: stale rules are closer to the user's intent than no rules.
func (c *Checker) RefreshRegexLists() error {
	if c == nil || c.gravityDB == nil {
		return nil
	}

	allowRaw, err := c.regexPatterns(regexAllowView)
	if err != nil {
		return err
	}

	denyRaw, err := c.regexPatterns(regexDenyView)
	if err != nil {
		return err
	}

	if current := c.regex.Load(); current != nil &&
		slices.Equal(current.allowRaw, allowRaw) && slices.Equal(current.denyRaw, denyRaw) {
		return nil
	}

	lists := &regexLists{
		allowRaw: allowRaw,
		denyRaw:  denyRaw,
		allow:    compileRegexRules(allowRaw, true),
		deny:     compileRegexRules(denyRaw, false),
	}
	c.regex.Store(lists)
	slog.Info("pi-hole regex lists loaded",
		"allow", len(lists.allow), "deny", len(lists.deny),
		"skipped", len(allowRaw)+len(denyRaw)-len(lists.allow)-len(lists.deny))

	return nil
}

func (c *Checker) regexPatterns(view string) ([]string, error) {
	rows, err := c.gravityDB.Query(fmt.Sprintf(`
		SELECT DISTINCT TRIM(domain)
		FROM %s
		WHERE TRIM(domain) <> ''
		ORDER BY TRIM(domain)
	`, view))
	if err != nil {
		return nil, fmt.Errorf("%s lookup failed: %w", view, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var patterns []string

	for rows.Next() {
		var pattern string
		if err := rows.Scan(&pattern); err != nil {
			return nil, fmt.Errorf("%s scan failed: %w", view, err)
		}

		patterns = append(patterns, pattern)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s iteration failed: %w", view, err)
	}

	return patterns, nil
}

// matchesRegex reports whether domain matches any loaded allow (or deny) regex rule.
func (c *Checker) matchesRegex(domain string, allow bool) bool {
	lists := c.regex.Load()
	if lists == nil {
		return false
	}

	rules := lists.deny
	if allow {
		rules = lists.allow
	}

	for _, rule := range rules {
		if rule.matches(domain) {
			return true
		}
	}

	return false
}
