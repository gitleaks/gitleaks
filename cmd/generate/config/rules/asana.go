package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
		RuleID:      "asana-client-id",
		Regex:       generateSemiGenericRegex([]string{"asana"}, numeric("16"), true),
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		generateSampleSecret("asana", secrets.NewSecret(numeric("16"))),
	}
	return validate(r, tps, nil)
}

func AsanaClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.",
		RuleID:      "asana-client-secret",
		Regex:       generateSemiGenericRegex([]string{"asana"}, alphaNumeric("32"), true),

		Keywords: []string{"asana"},
	}

	// validate
	tps := []string{
		generateSampleSecret("asana", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
