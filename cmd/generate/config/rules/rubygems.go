package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func RubyGemsAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rubygems-api-token",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		Regex:       utils.GenerateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false),
		Entropy:     2,
		Keywords: []string{
			"rubygems_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("rubygemsAPIToken", "rubygems_"+secrets.NewSecret(utils.Hex("48")))
	return utils.Validate(r, tps, nil)
}
