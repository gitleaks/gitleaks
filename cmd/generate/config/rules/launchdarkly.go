package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LaunchDarklyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "launchdarkly-access-token",
		Description: "Launchdarkly Access Token",
		Regex:       generateSemiGenericRegex([]string{"launchdarkly"}, alphaNumericExtended("40")),
		SecretGroup: 1,
		Keywords: []string{
			"launchdarkly",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("launchdarkly", secrets.NewSecret(alphaNumericExtended("40"))),
	}
	return validate(r, tps, nil)
}
