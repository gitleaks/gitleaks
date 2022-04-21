package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NPM() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "npm-access-token",
		Description: "npm access token",
		Regex:       generateUniqueTokenRegex(`npm_[a-z0-9]{36}`),
		SecretGroup: 1,
		Keywords: []string{
			"npm_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("npmAccessToken", "npm_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}
