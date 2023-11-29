package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendbirdAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-token",
		Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, hex("40"), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sendbird", secrets.NewSecret(hex("40"))),
	}
	return validate(r, tps, nil)
}

func SendbirdAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-id",
		Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, hex8_4_4_4_12(), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sendbird", secrets.NewSecret(hex8_4_4_4_12())),
	}
	return validate(r, tps, nil)
}
