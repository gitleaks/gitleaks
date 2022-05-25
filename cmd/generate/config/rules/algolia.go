package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AlgoliaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Algolia API Key",
		RuleID:      "algolia-api-key",
		Regex:       generateSemiGenericRegex([]string{"algolia"}, `[a-z0-9]{32}`),
		Keywords:    []string{"algolia"},
	}

	// validate
	tps := []string{
		"algolia_key := " + secrets.NewSecret(hex("32")),
	}
	return validate(r, tps, nil)
}
