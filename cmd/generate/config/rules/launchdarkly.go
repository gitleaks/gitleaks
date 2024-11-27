package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LaunchDarklyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "launchdarkly-access-token",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"launchdarkly"}, utils.AlphaNumericExtended("40"), true),

		Keywords: []string{
			"launchdarkly",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("launchdarkly", secrets.NewSecret(utils.AlphaNumericExtended("40")))
	return utils.Validate(r, tps, nil)
}
