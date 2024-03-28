package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		Regex: generateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, alphaNumeric("16"), true),

		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("linkedin", secrets.NewSecret(alphaNumeric("16"))),
	}
	return validate(r, tps, nil)
}

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		Regex: generateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, alphaNumeric("14"), true),

		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("linkedin", secrets.NewSecret(alphaNumeric("14"))),
	}
	return validate(r, tps, nil)
}
