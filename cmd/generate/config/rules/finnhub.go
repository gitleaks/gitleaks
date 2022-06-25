package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FinnhubAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "finnhub-access-token",
		Description: "Finnhub Access Token",
		Regex:       generateSemiGenericRegex([]string{"finnhub"}, alphaNumeric("20")),
		SecretGroup: 1,
		Keywords: []string{
			"finnhub",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("finnhub", secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}
