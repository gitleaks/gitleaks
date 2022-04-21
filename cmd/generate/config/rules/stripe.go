package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func StripeAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Stripe",
		RuleID:      "stripe-access-token",
		Regex:       regexp.MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`),
		Keywords: []string{
			"sk_test",
			"pk_test",
			"sk_live",
			"pk_live",
		},
	}

	// validate
	tps := []string{"stripeToken := \"sk_test_" + secrets.NewSecret(alphaNumeric("30")) + "\""}
	return validate(r, tps, nil)
}
