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
		Regex:       utils.GenerateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true),
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("npmAccessToken", "npm_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	return utils.Validate(r, tps, nil)
}
