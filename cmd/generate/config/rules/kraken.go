package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KrakenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kraken-access-token",
		Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
		Regex: utils.GenerateSemiGenericRegex([]string{"kraken"},
			utils.AlphaNumericExtendedLong("80,90"), true),

		Keywords: []string{
			"kraken",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("kraken", secrets.NewSecret(utils.AlphaNumericExtendedLong("80,90")))
	return utils.Validate(r, tps, nil)
}
