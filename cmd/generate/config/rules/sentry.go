package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SentryAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sentry-access-token",
		Description: "Sentry Access Token",
		Regex:       generateSemiGenericRegex([]string{"sentry"}, hex("64")),
		SecretGroup: 1,
		Keywords: []string{
			"sentry",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sentry", secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
