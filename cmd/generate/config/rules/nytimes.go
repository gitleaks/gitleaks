package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NytimesAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "nytimes-access-token",
		Description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
		Regex: generateSemiGenericRegex([]string{
			"nytimes", "new-york-times,", "newyorktimes"},
			alphaNumericExtended("32"), true),

		Keywords: []string{
			"nytimes",
			"new-york-times",
			"newyorktimes",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("nytimes", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
