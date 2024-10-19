package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Snyk() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "snyk-api-token",
		Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, utils.Hex8_4_4_4_12(), true),
		Entropy:     3,
		Keywords:    []string{"snyk"},
	}

	// validate
	tps := []string{
		`const SNYK_TOKEN = "f25efc9e-7c29-49d6-87d9-263a8ee74d7d"`, // gitleaks:allow
		`const SNYK_KEY = "893a0e88-cf91-411b-90c9-8b1305d6740c"`,   // gitleaks:allow
		`SNYK_TOKEN := "2832e7a4-03b9-43b8-ada3-b15dc2d1d65d"`,      // gitleaks:allow
		`SNYK_TOKEN ::= "94722f35-d992-497f-8044-fa7d21577138"`,     // gitleaks:allow
		`SNYK_TOKEN :::= "f25efc9e-7c29-49d6-87d9-263a8ee74d7d"`,    // gitleaks:allow
		`SNYK_TOKEN ?= "2832e7a4-03b9-43b8-ada3-b15dc2d1d65d"`,      // gitleaks:allow
		`SNYK_API_KEY ?= "94722f35-d992-497f-8044-fa7d21577138"`,    // gitleaks:allow
		`SNYK_API_TOKEN = "f25efc9e-7c29-49d6-87d9-263a8ee74d7d"`,   // gitleaks:allow
		`SNYK_OAUTH_TOKEN = "893a0e88-cf91-411b-90c9-8b1305d6740c"`, // gitleaks:allow
	}
	fps := []string{
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
