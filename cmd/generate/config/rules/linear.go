package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
		RuleID:      "linear-api-key",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("linear", "lin_api_"+secrets.NewSecret(utils.AlphaNumeric("40"))),
	}
	return utils.Validate(r, tps, nil)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
		RuleID:      "linear-client-secret",
		Regex:       utils.GenerateSemiGenericRegex([]string{"linear"}, utils.Hex("32"), true),
		Keywords:    []string{"linear"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("linear", secrets.NewSecret(utils.Hex("32"))),
	}
	return utils.Validate(r, tps, nil)
}
