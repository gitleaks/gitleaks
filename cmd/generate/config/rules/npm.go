package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NPM() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "npm-access-token",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		Regex:       utils.GenerateUniqueTokenRegex(`npm_[a-zA-Z0-9]{36}`, false),
		Entropy:     4,
		Keywords: []string{
			"npm_",
		},
		Verify: &config.Verify{
			HTTPVerb: "GET",
			URL:      "https://registry.npmjs.org/-/whoami",
			Headers: map[string]string{
				"Authorization": "Bearer ${npm-access-token}",
				"Content-Type":  "application/json",
			},
			ExpectedStatus: []int{200},
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("npmAccessToken", "npm_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	fps := []string{
		`   //registry.npmjs.org/:_authToken=npm_000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
