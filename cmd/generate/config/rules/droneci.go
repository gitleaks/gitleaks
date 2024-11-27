package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DroneciAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "droneci-access-token",
		Description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"droneci"}, utils.AlphaNumeric("32"), true),

		Keywords: []string{
			"droneci",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("droneci", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
