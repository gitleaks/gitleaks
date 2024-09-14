package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleID:      "finicity-client-secret",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, alphaNumeric("20"), true),

		Keywords: []string{"finicity"},
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
		Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
		RuleID:      "finicity-api-token",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, hex("32"), true),

		Keywords: []string{"finicity"},
	}

	// validate
	tps := []string{
		generateSampleSecret("finicity", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
