package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendbirdAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-token",
		Description: "Sendbird Access Token",
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, hex("40")),
		SecretGroup: 1,
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
		Description: "Sendbird Access ID",
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, hex8_4_4_4_12()),
		SecretGroup: 1,
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
