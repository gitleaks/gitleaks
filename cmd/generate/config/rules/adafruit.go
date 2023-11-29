package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Regex:       generateSemiGenericRegex([]string{"adafruit"}, alphaNumericExtendedShort("32"), true),
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := []string{
		generateSampleSecret("adafruit", secrets.NewSecret(alphaNumericExtendedShort("32"))),
	}
	return validate(r, tps, nil)
}
