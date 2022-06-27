package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KucoinAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kucoin-access-token",
		Description: "Kucoin Access Token",
		Regex:       generateSemiGenericRegex([]string{"kucoin"}, hex("24")),
		SecretGroup: 1,
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
		Description: "Kucoin Secret Key",
		Regex:       generateSemiGenericRegex([]string{"kucoin"}, hex8_4_4_4_12()),
		SecretGroup: 1,
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
