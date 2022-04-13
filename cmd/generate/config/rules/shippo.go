package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func ShippoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shippo-api-token",
		Description: "Shippo API token",
		Regex:       generateUniqueTokenRegex(`shippo_(live|test)_[a-f0-9]{40}`),
		SecretGroup: 1,
		Keywords: []string{
			"shippo_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("shippo", "shippo_live_"+sampleHex40Token),
		generateSampleSecret("shippo", "shippo_test_"+sampleHex40Token),
	}
	return validate(r, tps)
}
