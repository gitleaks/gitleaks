package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Duffel() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "duffel-api-token",
		Description: "Duffel API token",
		Regex:       regexp.MustCompile(`duffel_(test|live)_(?i)[a-z0-9_\-=]{43}`),
		Keywords:    []string{"duffel"},
	}

	// validate
	tps := []string{
		generateSampleSecret("duffel", "duffel_test_"+secrets.NewSecret(alphaNumericExtended("43"))),
	}
	return validate(r, tps, nil)
}
