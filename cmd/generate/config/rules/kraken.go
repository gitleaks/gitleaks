package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KrakenAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "kraken-access-token",
		Description: "Kraken Access Token",
		Regex: generateSemiGenericRegex([]string{"kraken"},
			alphaNumericExtendedLong("80,90")),
		SecretGroup: 1,
		Keywords: []string{
			"kraken",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("kraken",
			secrets.NewSecret(alphaNumericExtendedLong("80,90"))),
	}
	return validate(r, tps, nil)
}
