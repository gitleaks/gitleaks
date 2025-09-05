package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleID:      "finicity-client-secret",
		Regex:       utils.GenerateSemiGenericRegex([]string{"finicity"}, utils.AlphaNumeric("20"), true),

		Keywords: []string{"finicity"},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("finicity", secrets.NewSecret(utils.AlphaNumeric("20")))
	return &r
}

func FinicityAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
		RuleID:      "finicity-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"finicity"}, utils.Hex("32"), true),

		Keywords: []string{"finicity"},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("finicity", secrets.NewSecret(utils.Hex("32")))
	return &r
}
