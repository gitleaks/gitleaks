package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func StripeAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "stripe-access-token",
		Description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`, false),
		Entropy:     2,
		Keywords: []string{
			"sk_test",
			"sk_live",
			"sk_prod",
			"rk_test",
			"rk_live",
			"rk_prod",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("stripe", "sk_test_"+secrets.NewSecret(utils.AlphaNumeric("30")))
	tps = append(tps, utils.GenerateSampleSecrets("stripe", "sk_prod_"+secrets.NewSecret(utils.AlphaNumeric("99")))...)
	tps = append(tps,
		"sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs", // gitleaks:allow
		"rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon", // gitleaks:allow
	)
	fps := []string{"nonMatchingToken := \"task_test_" + secrets.NewSecret(utils.AlphaNumeric("30")) + "\""}
	return utils.Validate(r, tps, fps)
}
