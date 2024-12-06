package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func SquareSpaceAccessToken() *rule.Rule {
	// define rule
	r := rule.Rule{
		RuleID:      "squarespace-access-token",
		Description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"squarespace"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"squarespace",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("squarespace", secrets.NewSecret(utils.Hex8_4_4_4_12()))
	return utils.Validate(r, tps, nil)
}
