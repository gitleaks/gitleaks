package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TravisCIAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "travisci-access-token",
		Description: "Travis CI Access Token",
		Regex:       generateSemiGenericRegex([]string{"travis"}, alphaNumeric("22")),
		SecretGroup: 1,
		Keywords: []string{
			"travis",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("travis", secrets.NewSecret(alphaNumeric("22"))),
	}
	return validate(r, tps, nil)
}
