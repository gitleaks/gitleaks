package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AlgoliaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
		RuleID:      "algolia-api-key",
		Regex:       generateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`, true),
		Keywords:    []string{"algolia"},
	}

	// validate
	tps := []string{
		"algolia_key := " + secrets.NewSecret(hex("32")),
	}
	return validate(r, tps, nil)
}
