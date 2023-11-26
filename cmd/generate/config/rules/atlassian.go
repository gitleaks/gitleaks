package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Atlassian() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.",
		RuleID:      "atlassian-api-token",
		Regex: generateSemiGenericRegex([]string{
			"atlassian", "confluence", "jira"}, alphaNumeric("24"), true),
		Keywords: []string{"atlassian", "confluence", "jira"},
	}

	// validate
	tps := []string{
		generateSampleSecret("atlassian", secrets.NewSecret(alphaNumeric("24"))),
		generateSampleSecret("confluence", secrets.NewSecret(alphaNumeric("24"))),
	}
	return validate(r, tps, nil)
}
