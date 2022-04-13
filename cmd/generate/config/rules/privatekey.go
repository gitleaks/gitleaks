package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PrivateKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Private Key",
		RuleID:      "private-key",
		Regex:       regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`),
		Keywords:    []string{"-----BEGIN PRIVATE"},
	}

	// validate
	tps := []string{`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`} // gitleaks:allow
	return validate(r, tps)
}
