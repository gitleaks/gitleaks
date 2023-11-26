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
		Regex:       generateUniqueTokenRegex(`(sk|pk)_(test|live)_[0-9a-z]{10,32}`, true),
		Keywords: []string{
			"sk_test",
			"pk_test",
			"sk_live",
			"pk_live",
		},
	}

	// validate
	tps := []string{"stripeToken := \"sk_test_" + secrets.NewSecret(alphaNumeric("30")) + "\""}
	fps := []string{"nonMatchingToken := \"task_test_" + secrets.NewSecret(alphaNumeric("30")) + "\""}
	return validate(r, tps, fps)
}
