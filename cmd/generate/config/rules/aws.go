package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "AWS",
		RuleID:      "aws-access-token",
		Regex: regexp.MustCompile(
			"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
		Keywords: []string{
			"AKIA",
			"AGPA",
			"AIDA",
			"AROA",
			"AIPA",
			"ANPA",
			"ANVA",
			"ASIA",
		},
	}

	// validate
	tps := []string{generateSampleSecret("AWS", "AKIALALEMEL33243OLIB")} // gitleaks:allow
	return validate(r, tps, nil)
}
