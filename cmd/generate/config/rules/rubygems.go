package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func RubyGemsAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rubygems-api-token",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		Regex:       generateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, true),

		Keywords: []string{
			"rubygems_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("rubygemsAPIToken", "rubygems_"+secrets.NewSecret(hex("48"))),
	}
	return validate(r, tps, nil)
}
