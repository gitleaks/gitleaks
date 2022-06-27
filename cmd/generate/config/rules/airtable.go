package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Airtable() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Airtable API Key",
		RuleID:      "airtable-api-key",
		Regex:       generateSemiGenericRegex([]string{"airtable"}, alphaNumeric("17")),
		SecretGroup: 1,
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := []string{
		generateSampleSecret("airtable", secrets.NewSecret(alphaNumeric("17"))),
	}
	return validate(r, tps, nil)
}
