package rules

import (
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
		}, alphaNumeric25),
		SecretGroup: 1,
		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("messagebird", sampleAlphaNumeric25Token),
		generateSampleSecret("message-bird", sampleAlphaNumeric25Token),
		generateSampleSecret("message_bird", sampleAlphaNumeric25Token),
	}
	return validate(r, tps)
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
		}, `[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}`),
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
	return validate(r, tps)
}
