package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
		Regex:       generateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true),

		Keywords: []string{
			"live_",
			"gocardless",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gocardless", "live_"+secrets.NewSecret(alphaNumericExtended("40"))),
	}
	return validate(r, tps, nil)
}
