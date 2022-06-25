package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func RapidAPIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rapidapi-access-token",
		Description: "RapidAPI Access Token",
		Regex: generateSemiGenericRegex([]string{"rapidapi"},
			alphaNumericExtendedShort("50")),
		SecretGroup: 1,
		Keywords: []string{
			"rapidapi",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("rapidapi",
			secrets.NewSecret(alphaNumericExtendedShort("50"))),
	}
	return validate(r, tps, nil)
}
