package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DatadogtokenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datadog-access-token",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		Regex: utils.GenerateSemiGenericRegex([]string{"datadog"},
			utils.AlphaNumeric("40"), true),
		Keywords: []string{
			"datadog",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("datadog", secrets.NewSecret(utils.AlphaNumeric("40")))
	return utils.Validate(r, tps, nil)
}
