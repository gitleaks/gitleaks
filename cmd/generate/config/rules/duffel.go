package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Duffel() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "duffel-api-token",
		Description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		Regex:       regexp.MustCompile(`duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`),
		Keywords:    []string{"duffel"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("duffel", "duffel_test_"+secrets.NewSecret(utils.AlphaNumericExtended("43"))),
	}
	return utils.Validate(r, tps, nil)
}
