package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Duffel() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "duffel-api-token",
		Description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		Regex:       regexp.MustCompile(`duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`),
		Entropy:     2,
		Keywords:    []string{"duffel_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("duffel", "duffel_test_"+secrets.NewSecret(utils.AlphaNumericExtended("43")))
	return utils.Validate(r, tps, nil)
}
