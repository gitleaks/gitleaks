package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ShippoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shippo-api-token",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		Regex:       utils.GenerateUniqueTokenRegex(`shippo_(live|test)_[a-f0-9]{40}`, true),

		Keywords: []string{
			"shippo_",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("shippo", "shippo_live_"+secrets.NewSecret(utils.Hex("40"))),
		utils.GenerateSampleSecret("shippo", "shippo_test_"+secrets.NewSecret(utils.Hex("40"))),
	}
	return utils.Validate(r, tps, nil)
}
