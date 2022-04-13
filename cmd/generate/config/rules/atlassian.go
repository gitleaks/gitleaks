package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Atlassian() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Atlassian API token",
		RuleID:      "atlassian-api-token",
		Regex:       generateSemiGenericRegex([]string{"atlassian"}, alphaNumeric24),
		SecretGroup: 1,
		Keywords:    []string{"atlassian"},
	}

	// validate
	tps := []string{
		"atlassian:= \"" + sampleAlphaNumeric24Token + "\"",
	}
	return validate(r, tps)
}
