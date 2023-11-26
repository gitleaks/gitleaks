package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KucoinAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-access-token",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		Regex:       generateSemiGenericRegex([]string{"kucoin"}, hex("24"), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("kucoin", secrets.NewSecret(hex("24"))),
	}
	return validate(r, tps, nil)
}

func KucoinSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-secret-key",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		Regex:       generateSemiGenericRegex([]string{"kucoin"}, hex8_4_4_4_12(), true),

		Keywords: []string{
			"kucoin",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("kucoin", secrets.NewSecret(hex8_4_4_4_12())),
	}
	return validate(r, tps, nil)
}
