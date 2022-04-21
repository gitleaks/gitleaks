package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
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
		generateSampleSecret("shippo", "shippo_live_"+secrets.NewSecret(hex("40"))),
		generateSampleSecret("shippo", "shippo_test_"+secrets.NewSecret(hex("40"))),
	}
	return validate(r, tps, nil)
}
