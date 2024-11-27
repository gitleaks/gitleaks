package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NytimesAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "nytimes-access-token",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"nytimes", "new-york-times,", "newyorktimes"},
			utils.AlphaNumericExtended("32"), true),

		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("nytimes", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
