package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SumoLogicAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "SumoLogic Access ID",
		Regex: generateSemiGenericRegex([]string{"sumo"},
			alphaNumeric("14")),
		SecretGroup: 1,
		Keywords: []string{
			"sumo",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sumo", secrets.NewSecret(alphaNumeric("14"))),
	}
	return validate(r, tps, nil)
}

func SumoLogicAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "SumoLogic Access Token",
		Regex: generateSemiGenericRegex([]string{"sumo"},
			alphaNumeric("64")),
		SecretGroup: 1,
		Keywords: []string{
			"sumo",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sumo", secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
