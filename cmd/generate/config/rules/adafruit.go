package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adafruit"}, utils.AlphaNumericExtendedShort("32"), true),
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adafruit", secrets.NewSecret(utils.AlphaNumericExtendedShort("32")))
	return utils.Validate(r, tps, nil)
}
