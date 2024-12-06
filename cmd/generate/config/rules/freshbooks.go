package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func FreshbooksAccessToken() *rule.Rule {
	// define rule
	r := rule.Rule{
		RuleID:      "freshbooks-access-token",
		Description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"freshbooks"}, utils.AlphaNumeric("64"), true),

		Keywords: []string{
			"freshbooks",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("freshbooks", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}
