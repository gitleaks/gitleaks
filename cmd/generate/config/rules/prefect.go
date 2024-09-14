package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Prefect() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "prefect-api-token",
		Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
		Regex:       generateUniqueTokenRegex(`pnu_[a-z0-9]{36}`, true),

		Keywords: []string{
			"pnu_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("api-token", "pnu_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}
