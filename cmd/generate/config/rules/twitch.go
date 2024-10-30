package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TwitchAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twitch-api-token",
		Description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitch"}, utils.AlphaNumeric("30"), true),
		Keywords: []string{
			"twitch",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitch", secrets.NewSecret(utils.AlphaNumeric("30")))
	return utils.Validate(r, tps, nil)
}
