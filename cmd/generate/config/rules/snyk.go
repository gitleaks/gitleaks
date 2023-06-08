package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Snyk() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Snyk API token",
		RuleID:      "snyk-api-token",
		SecretGroup: 1,
		Regex:       generateSemiGenericRegex([]string{"snyk_token"}, hex8_4_4_4_12()),
		Keywords:    []string{"snyk_token"},
	}

	// validate
	tps := []string{
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
