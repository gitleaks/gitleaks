package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DatadogtokenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "datadog-access-token",
		Description: "Datadog Access Token",
		Regex: generateSemiGenericRegex([]string{"datadog"},
			alphaNumeric("40")),
		SecretGroup: 1,
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
