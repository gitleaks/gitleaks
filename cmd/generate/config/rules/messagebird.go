package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MessageBirdAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "MessageBird API token",
		RuleID:      "messagebird-api-token",
		Regex: generateSemiGenericRegex([]string{
			"messagebird",
			"message-bird",
			"message_bird",
		}, alphaNumeric("25")),
		SecretGroup: 1,
		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("messagebird", secrets.NewSecret(alphaNumeric("25"))),
		generateSampleSecret("message-bird", secrets.NewSecret(alphaNumeric("25"))),
		generateSampleSecret("message_bird", secrets.NewSecret(alphaNumeric("25"))),
	}
	return validate(r, tps, nil)
}

func MessageBirdClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "MessageBird client ID",
		RuleID:      "messagebird-client-id",
		Regex: generateSemiGenericRegex([]string{
			"messagebird",
			"message-bird",
			"message_bird",
		}, hex8_4_4_4_12()),
		SecretGroup: 1,
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
	return validate(r, tps, nil)
}
