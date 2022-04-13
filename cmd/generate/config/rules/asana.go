package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Asana Client ID",
		RuleID:      "asana-client-id",
		Regex:       generateSemiGenericRegex([]string{"asana"}, numeric16),
		SecretGroup: 1,
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		"asanaKey := \"" + sampleNumeric16 + "\"",
	}
	return validate(r, tps)
}

func AsanaClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Asana Client Secret",
		RuleID:      "asana-client-secret",
		Regex:       generateSemiGenericRegex([]string{"asana"}, alphaNumeric32),
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		"asanaKey := \"" + sampleAlphaNumeric32Token + "\"",
	}
	return validate(r, tps)
}
