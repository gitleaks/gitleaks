package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlaidAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-client-id",
		Description: "Plaid Client ID",
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

func PlaidSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-secret-key",
		Description: "Plaid Secret key",
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

func PlaidAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-api-token",
		Description: "Plaid API Token",
		Regex: generateSemiGenericRegex([]string{"plaid"},
			fmt.Sprintf("access-(?:sandbox|development|production)-%s", hex8_4_4_4_12())),
		SecretGroup: 1,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("plaid", secrets.NewSecret(fmt.Sprintf("access-(?:sandbox|development|production)-%s", hex8_4_4_4_12()))),
	}
	return validate(r, tps, nil)
}
