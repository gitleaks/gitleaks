package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func NetlifyAccessToken() *rule.Rule {
	// define rule
	r := rule.Rule{
		RuleID:      "netlify-access-token",
		Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
		Regex: utils.GenerateSemiGenericRegex([]string{"netlify"},
			utils.AlphaNumericExtended("40,46"), true),

		Keywords: []string{
			"netlify",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("netlify", secrets.NewSecret(utils.AlphaNumericExtended("40,46")))
	return utils.Validate(r, tps, nil)
}
