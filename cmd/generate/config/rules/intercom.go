package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func Intercom() *rule.Rule {
	// define rule
	r := rule.Rule{
		Description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
		RuleID:      "intercom-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"intercom"}, utils.AlphaNumericExtended("60"), true),

		Keywords: []string{"intercom"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("intercom", secrets.NewSecret(utils.AlphaNumericExtended("60")))
	return utils.Validate(r, tps, nil)
}
