package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Snyk() *config.Rule {

	keywords := []string{
		"snyk_token",
		"snyk_key",
		"snyk_api_token",
		"snyk_api_key",
		"snyk_oauth_token",
	}

	// define rule
	r := config.Rule{
		Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "snyk-api-token",

		Regex:    generateSemiGenericRegex(keywords, hex8_4_4_4_12(), true),
		Keywords: keywords,
	}

	// validate
	tps := []string{
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		`const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,     // gitleaks:allow
		`SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
