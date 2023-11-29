package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func JFrogAPIKey() *config.Rule {
	keywords := []string{"jfrog", "artifactory", "bintray", "xray"}

	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",

		// Unique ID for the rule
		RuleID: "jfrog-api-key",

		// Regex capture group for the actual secret

		// Regex used for detecting secrets. See regex section below for more details
		Regex: generateSemiGenericRegex(keywords, alphaNumeric("73"), true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: keywords,
	}
	// validate
	tps := []string{
		fmt.Sprintf("--set imagePullSecretJfrog.password=%s", secrets.NewSecret(alphaNumeric("73"))),
	}
	return validate(r, tps, nil)
}

func JFrogIdentityToken() *config.Rule {
	keywords := []string{"jfrog", "artifactory", "bintray", "xray"}

	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",

		// Unique ID for the rule
		RuleID: "jfrog-identity-token",

		// Regex capture group for the actual secret

		// Regex used for detecting secrets. See regex section below for more details
		Regex: generateSemiGenericRegex(keywords, alphaNumeric("64"), true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: keywords,
	}

	// validate
	tps := []string{
		generateSampleSecret("jfrog", secrets.NewSecret(alphaNumeric("64"))),
		generateSampleSecret("artifactory", secrets.NewSecret(alphaNumeric("64"))),
		generateSampleSecret("bintray", secrets.NewSecret(alphaNumeric("64"))),
		generateSampleSecret("xray", secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
