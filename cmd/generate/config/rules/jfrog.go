package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func JFrogAPIKey() *config.Rule {
	keywords := []string{"jfrog", "artifactory", "bintray", "xray"}

	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "JFrog API Key",

		// Unique ID for the rule
		RuleID: "jfrog-api-key",

		// Regex capture group for the actual secret
		SecretGroup: 1,

		// Regex used for detecting secrets. See regex section below for more details
		Regex: generateSemiGenericRegex(keywords, alphaNumeric("73")),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: keywords,
	}

	// validate
	tps := []string{
		generateSampleSecret("jfrog", secrets.NewSecret(alphaNumeric("73"))),
	}
	return validate(r, tps, nil)
}
