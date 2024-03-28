package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func InfracostAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",

		// Unique ID for the rule
		RuleID: "infracost-api-token",

		// Regex capture group for the actual secret

		// Regex used for detecting secrets. See regex section below for more details
		Regex: generateUniqueTokenRegex(`ico-[a-zA-Z0-9]{32}`, true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: []string{"ico-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("ico", "ico-"+secrets.NewSecret("[A-Za-z0-9]{32}")),
	}
	return validate(r, tps, nil)
}
