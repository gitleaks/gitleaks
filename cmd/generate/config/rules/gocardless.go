package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "GoCardless API token",
		Regex:       generateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`),
		Keywords: []string{
			"live_",
			"gocardless",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gocardless", "live_"+sampleExtendedAlphaNumeric40Token),
	}
	return validate(r, tps)
}
