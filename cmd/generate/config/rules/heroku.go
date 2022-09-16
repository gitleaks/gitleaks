package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Heroku() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Heroku API Key",
		RuleID:      "heroku-api-key",
		Regex:       generateSemiGenericRegex([]string{"heroku"}, hex8_4_4_4_12()),
		SecretGroup: 1,
		Keywords:    []string{"heroku"},
	}

	// validate
	tps := []string{
		`const HEROKU_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
