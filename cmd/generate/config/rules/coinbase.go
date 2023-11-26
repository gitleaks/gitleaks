package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CoinbaseAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "coinbase-access-token",
		Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
		Regex: generateSemiGenericRegex([]string{"coinbase"},
			alphaNumericExtendedShort("64"), true),
		Keywords: []string{
			"coinbase",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("coinbase",
			secrets.NewSecret(alphaNumericExtendedShort("64"))),
	}
	return validate(r, tps, nil)
}
