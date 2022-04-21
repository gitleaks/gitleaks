package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity Client Secret",
		RuleID:      "finicity-client-secret",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, alphaNumeric("20")),
		SecretGroup: 1,
		Keywords:    []string{"finicity"},
	}

	// validate
	tps := []string{
		generateSampleSecret("finicity", secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}

func FinicityAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity API token",
		RuleID:      "finicity-api-token",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, hex("32")),
		SecretGroup: 1,
		Keywords:    []string{"finicity"},
	}

	// validate
	tps := []string{
		generateSampleSecret("finicity", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
