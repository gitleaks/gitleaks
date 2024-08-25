package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MattermostAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mattermost-access-token",
		Description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mattermost"}, utils.AlphaNumeric("26"), true),

		Keywords: []string{
			"mattermost",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mattermost", secrets.NewSecret(utils.AlphaNumeric("26")))
	return utils.Validate(r, tps, nil)
}
