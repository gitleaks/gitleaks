package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func StripeAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
		RuleID:      "stripe-access-token",
		Regex:       generateUniqueTokenRegex(`(sk|rk)_(test|live|prod)_[0-9a-z]{10,99}`, true),
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
	tps := []string{
		"stripeToken := \"sk_test_" + secrets.NewSecret(alphaNumeric("30")) + "\"",
		"sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs", // gitleaks:allow
		"rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon", // gitleaks:allow
	}
	fps := []string{"nonMatchingToken := \"task_test_" + secrets.NewSecret(alphaNumeric("30")) + "\""}
	return validate(r, tps, fps)
}
