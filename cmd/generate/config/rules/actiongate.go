package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ActionGateProveToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "actiongate-prove-token",
		Description: "Detected an ActionGate Prove Token, risking unauthorized bypass of AI agent execution boundaries and cryptographic audit gates.",
		Regex:       utils.GenerateUniqueTokenRegex(`prov_(?:live|test)_[0-9a-f]{32}`, false),
		Keywords: []string{
			"prov_live_",
			"prov_test_",
		},
	}

	// validate
	tps := []string{
		"prov_live_99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4",
		"prov_test_0123456789abcdef0123456789abcdef",
		utils.GenerateSampleSecret("actiongate", "prov_live_"+secrets.NewSecret(utils.Hex("32"))),
	}

	fps := []string{
		// Too short
		"prov_live_99a8b7c6d5e4f3a2",
		// Invalid characters
		"prov_live_zzzaaaxyz0123456789abcdef0123456",
		// Wrong prefix
		"prov_fake_99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4",
	}

	return utils.Validate(r, tps, fps)
}
