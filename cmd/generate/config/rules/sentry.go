package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SentryAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sentry-access-token",
		Description: "Found a Sentry Access Token, risking unauthorized access to error tracking services and sensitive application data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sentry"}, utils.Hex("64"), true),

		Keywords: []string{
			"sentry",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("sentry", secrets.NewSecret(utils.Hex("64"))),
	}
	return utils.Validate(r, tps, nil)
}
