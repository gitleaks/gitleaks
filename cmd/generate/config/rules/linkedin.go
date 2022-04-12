package rules

import (
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
		}, alphaNumeric16),
		SecretGroup: 1,
		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("linkedin", sampleAlphaNumeric16Token),
	}
	return validate(r, tps)
}

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Description: "LinkedIn Client ID",
		Regex: generateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, alphaNumeric14),
		SecretGroup: 1,
		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("linkedin", sampleAlphaNumeric14Token),
	}
	return validate(r, tps)
}
