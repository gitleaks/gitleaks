package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DatadogtokenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datadog-access-token",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		Regex: generateSemiGenericRegex([]string{"datadog"},
			alphaNumeric("40"), true),
		Keywords: []string{
			"datadog",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("datadog", secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}
