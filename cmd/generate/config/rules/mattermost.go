package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MattermostAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mattermost-access-token",
		Description: "Mattermost Access Token",
		Regex:       generateSemiGenericRegex([]string{"mattermost"}, alphaNumeric("26")),
		SecretGroup: 1,
		Keywords: []string{
			"mattermost",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mattermost", secrets.NewSecret(alphaNumeric("26"))),
	}
	return validate(r, tps, nil)
}
