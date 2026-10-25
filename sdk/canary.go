package sdk

import (
	"errors"
	"regexp"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	ckregexp "github.com/zricethezav/gitleaks/v8/regexp"
)

const canaryRuleID = "sdk-canary-token"

// AddCanaryRule appends a canary token rule to cfg.
//
// The generated rule matches values such as "org_canary_abc123..." or
// "honey-token-...", depending on the provided prefixes.
func AddCanaryRule(cfg *config.Config, prefixes ...string) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if len(prefixes) == 0 {
		prefixes = []string{"org_canary", "honeytoken", "canary"}
	}

	cleanPrefixes := normalizePrefixes(prefixes)
	if len(cleanPrefixes) == 0 {
		return errors.New("at least one non-empty canary prefix is required")
	}

	if cfg.Rules == nil {
		cfg.Rules = map[string]config.Rule{}
	}
	if cfg.Keywords == nil {
		cfg.Keywords = map[string]struct{}{}
	}

	cfg.Rules[canaryRuleID] = config.Rule{
		RuleID:      canaryRuleID,
		Description: "Detects canary or honeytoken markers for leak monitoring.",
		Regex:       buildCanaryPattern(cleanPrefixes),
		Keywords:    cleanPrefixes,
	}

	for _, prefix := range cleanPrefixes {
		cfg.Keywords[prefix] = struct{}{}
	}

	if !contains(cfg.OrderedRules, canaryRuleID) {
		cfg.OrderedRules = append(cfg.OrderedRules, canaryRuleID)
	}

	return nil
}

func buildCanaryPattern(prefixes []string) *ckregexp.Regexp {
	quoted := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		quoted = append(quoted, regexp.QuoteMeta(prefix))
	}

	// Prefix plus marker body to avoid noisy matches on plain words.
	pattern := `(?i)\b(?:` + strings.Join(quoted, "|") + `)[_.:-]?[a-z0-9][a-z0-9_-]{9,127}\b`
	return ckregexp.MustCompile(pattern)
}

func normalizePrefixes(prefixes []string) []string {
	seen := map[string]struct{}{}
	res := make([]string, 0, len(prefixes))

	for _, prefix := range prefixes {
		p := strings.ToLower(strings.TrimSpace(prefix))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		res = append(res, p)
	}

	return res
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
