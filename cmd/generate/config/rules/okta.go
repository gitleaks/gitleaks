package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OktaAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "okta-access-token",
		Description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
		Regex: utils.GenerateSemiGenericRegex([]string{"okta"},
			utils.AlphaNumericExtended("42"), true),

		Keywords: []string{
			"okta",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("okta", secrets.NewSecret(utils.AlphaNumeric("42"))),
	}
	return utils.Validate(r, tps, nil)
}
