package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlaidAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-client-id",
		Description: "Plaidkey Client ID",
		Regex:       generateSemiGenericRegex([]string{"plaid"}, alphaNumeric("24")),
		SecretGroup: 1,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("plaid", secrets.NewSecret(alphaNumeric("24"))),
	}
	return validate(r, tps, nil)
}

func PlaidAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-api-secret",
		Description: "Plaid API Secret",
		Regex:       generateSemiGenericRegex([]string{"plaid"}, alphaNumeric("30")),
		SecretGroup: 1,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("plaid", secrets.NewSecret(alphaNumeric("30"))),
	}
	return validate(r, tps, nil)
}
