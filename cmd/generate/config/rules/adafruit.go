package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Adafruit API Key",
		RuleID:      "adafruit-api-key",
		Regex:       generateSemiGenericRegex([]string{"adafruit"}, alphaNumericExtendedShort("32")),
		SecretGroup: 1,
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := []string{
		generateSampleSecret("adafruit", secrets.NewSecret(alphaNumericExtendedShort("32"))),
	}
	return validate(r, tps, nil)
}
