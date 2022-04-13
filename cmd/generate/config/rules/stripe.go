package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
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
	tps := []string{"stripeToken := \"sk_test_" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate stripe-access-token")
		}
	}
	return &r
}
