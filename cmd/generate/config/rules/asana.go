package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Asana Client ID",
		RuleID:      "asana-client-id",
		Regex:       generateSemiGenericRegex([]string{"asana"}, numeric("16")),
		SecretGroup: 1,
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
		Description: "Asana Client Secret",
		RuleID:      "asana-client-secret",
		Regex:       generateSemiGenericRegex([]string{"asana"}, alphaNumeric("32")),
		SecretGroup: 1,
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		generateSampleSecret("asana", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
