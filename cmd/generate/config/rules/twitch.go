package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twitch-api-token",
		Description: "Twitch API token",
		Regex:       generateSemiGenericRegex([]string{"twitch"}, alphaNumeric("30")),
		SecretGroup: 1,
		Keywords: []string{
			"twitch",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitch", secrets.NewSecret(alphaNumeric("30"))),
	}
	return validate(r, tps, nil)
}
