package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KucoinAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-access-token",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex("24"), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("kucoin", secrets.NewSecret(utils.Hex("24")))
	return utils.Validate(r, tps, nil)
}

func KucoinSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-secret-key",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("kucoin", secrets.NewSecret(utils.Hex8_4_4_4_12()))
	return utils.Validate(r, tps, nil)
}
