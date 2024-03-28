package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ScalingoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:      "scalingo-api-token",
		Regex:       regexp.MustCompile(`\btk-us-[a-zA-Z0-9-_]{48}\b`),
		Keywords:    []string{"tk-us-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("scalingo", "tk-us-"+secrets.NewSecret(alphaNumericExtendedShort("48"))),
	}
	return validate(r, tps, nil)
}
