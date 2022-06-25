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
<<<<<<< HEAD
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, `[0-9a-f]{40}`),
=======
		Regex:       generateSemiGenericRegex([]string{"sendbird"}, hex("40")),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
		SecretGroup: 1,
		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := []string{
<<<<<<< HEAD
		generateSampleSecret("sendbird", secrets.NewSecret(`[0-9a-f]{40}`)),
=======
		generateSampleSecret("sendbird", secrets.NewSecret(hex("40"))),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
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
<<<<<<< HEAD
		generateSampleSecret("sendbird", secrets.NewSecret(`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`)),
=======
		generateSampleSecret("sendbird", secrets.NewSecret(hex8_4_4_4_12())),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
	}
	return validate(r, tps, nil)
}
