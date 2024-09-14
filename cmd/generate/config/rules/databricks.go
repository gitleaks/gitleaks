package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Databricks() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		RuleID:      "databricks-api-token",
		Regex:       generateUniqueTokenRegex(`dapi[a-h0-9]{32}`, true),
		Keywords:    []string{"dapi"},
	}

	// validate
	tps := []string{
		generateSampleSecret("databricks", "dapi"+secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
