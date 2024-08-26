package rules

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlaidAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-client-id",
		Description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"plaid"}, utils.AlphaNumeric("24"), true),

		Entropy: 3.5,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("plaid", secrets.NewSecret(utils.AlphaNumeric("24"))),
	}
	return utils.Validate(r, tps, nil)
}

func PlaidSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-secret-key",
		Description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"plaid"}, utils.AlphaNumeric("30"), true),

		Entropy: 3.5,
		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("plaid", secrets.NewSecret(utils.AlphaNumeric("30"))),
	}
	return utils.Validate(r, tps, nil)
}

func PlaidAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "plaid-api-token",
		Description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
		Regex: utils.GenerateSemiGenericRegex([]string{"plaid"},
			fmt.Sprintf("access-(?:sandbox|development|production)-%s", utils.Hex8_4_4_4_12()), true),

		Keywords: []string{
			"plaid",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("plaid", secrets.NewSecret(fmt.Sprintf("access-(?:sandbox|development|production)-%s", utils.Hex8_4_4_4_12()))),
	}
	return utils.Validate(r, tps, nil)
}
