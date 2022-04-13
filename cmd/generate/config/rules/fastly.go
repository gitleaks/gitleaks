package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Fastly API key",
		RuleID:      "fastly-api-token",
		Regex:       generateSemiGenericRegex([]string{"fastly"}, extendedAlphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"fastly"},
	}

	// validate
	tps := []string{
		generateSampleSecret("fastly", sampleExtendedAlphaNumeric32Token),
	}
	return validate(r, tps)
}
