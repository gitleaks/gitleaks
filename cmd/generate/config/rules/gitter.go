package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func GitterAccessToken() *rule.Rule {
	// define rule
	r := rule.Rule{
		RuleID:      "gitter-access-token",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		Regex: utils.GenerateSemiGenericRegex([]string{"gitter"},
			utils.AlphaNumericExtendedShort("40"), true),

		Keywords: []string{
			"gitter",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gitter", secrets.NewSecret(utils.AlphaNumericExtendedShort("40")))
	return utils.Validate(r, tps, nil)
}
