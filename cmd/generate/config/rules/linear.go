package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-api-key",
		Description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Entropy:     2,
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("linear", "lin_api_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	return utils.Validate(r, tps, nil)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linear-client-secret",
		Description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"linear"}, utils.Hex("32"), true),
		Entropy:     2,
		Keywords:    []string{"linear"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("linear", secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}
