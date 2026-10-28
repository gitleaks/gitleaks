package utils

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestValidateAcceptsCompositeRules(t *testing.T) {
	withinLines := 1
	requiredRule := config.Rule{
		RuleID:      "username-rule",
		Description: "Username rule",
		Regex:       regexp.MustCompile(`username\s*=\s*"([^"]+)"`),
		SkipReport:  true,
	}
	primaryRule := config.Rule{
		RuleID:      "primary-rule",
		Description: "Primary rule",
		Regex:       regexp.MustCompile(`password\s*=\s*"([^"]+)"`),
		RequiredRules: []*config.Required{
			{
				RuleID:      requiredRule.RuleID,
				WithinLines: &withinLines,
			},
		},
	}

	rule := Validate(
		primaryRule,
		[]string{`username = "admin"` + "\n" + `password = "secret"`},
		[]string{`password = "secret"`, `username = "admin"`},
		&requiredRule,
	)

	if len(rule.RequiredRules) != 1 {
		t.Fatalf("expected required rule to be kept, got %d", len(rule.RequiredRules))
	}
}
