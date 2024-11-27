package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Snyk() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "snyk-api-token",

		Regex:    utils.GenerateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, utils.Hex8_4_4_4_12(), true),
		Keywords: []string{"snyk"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("snyk", "12345678-ABCD-ABCD-ABCD-1234567890AB")
	tps = append(tps,
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		`const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,     // gitleaks:allow
		`SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
