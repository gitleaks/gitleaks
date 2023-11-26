package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Regex:       generateSemiGenericRegex([]string{"intercom"}, alphaNumericExtended("60"), true),

		Keywords: []string{"intercom"},
	}

	// validate
	tps := []string{
		generateSampleSecret("intercom", secrets.NewSecret(alphaNumericExtended("60"))),
	}
	return validate(r, tps, nil)
}
