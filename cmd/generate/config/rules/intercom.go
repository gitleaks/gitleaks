package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Intercom API Token",
		RuleID:      "intercom-api-key",
		Regex:       generateSemiGenericRegex([]string{"intercom"}, extendedAlphaNumeric60),
		SecretGroup: 1,
		Keywords:    []string{"intercom"},
	}

	// validate
	tps := []string{
		generateSampleSecret("intercom", sampleExtendedAlphaNumeric60Token),
	}
	return validate(r, tps)
}
