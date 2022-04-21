package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Description: "LinkedIn Client secret",
		Regex: generateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, alphaNumeric("16")),
		SecretGroup: 1,
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
		Description: "LinkedIn Client ID",
		Regex: generateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, alphaNumeric("14")),
		SecretGroup: 1,
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
