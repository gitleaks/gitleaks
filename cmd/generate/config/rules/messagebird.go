package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MessageBirdAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
		RuleID:      "messagebird-api-token",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"messagebird",
			"message-bird",
			"message_bird",
		}, utils.AlphaNumeric("25"), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("messagebird", secrets.NewSecret(utils.AlphaNumeric("25"))),
		utils.GenerateSampleSecret("message-bird", secrets.NewSecret(utils.AlphaNumeric("25"))),
		utils.GenerateSampleSecret("message_bird", secrets.NewSecret(utils.AlphaNumeric("25"))),
	}
	return utils.Validate(r, tps, nil)
}

func MessageBirdClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
		RuleID:      "messagebird-client-id",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"messagebird",
			"message-bird",
			"message_bird",
		}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := []string{
		`const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return utils.Validate(r, tps, nil)
}
