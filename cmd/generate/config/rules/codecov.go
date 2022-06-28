package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CodecovAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "codecov-access-token",
		Description: "Codecov Access Token",
		Regex:       generateSemiGenericRegex([]string{"codecov"}, alphaNumeric("32")),
		SecretGroup: 1,
		Keywords: []string{
			"codecov",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("codecov", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
