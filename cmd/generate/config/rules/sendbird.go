package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendbirdAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-token",
		Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sendbird"}, utils.Hex("40"), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendbird", secrets.NewSecret(utils.Hex("40")))
	return utils.Validate(r, tps, nil)
}

func SendbirdAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-id",
		Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sendbird"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendbird", secrets.NewSecret(utils.Hex8_4_4_4_12()))
	return utils.Validate(r, tps, nil)
}
