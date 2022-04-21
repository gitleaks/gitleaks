package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LobPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Lob Publishable API Key",
		RuleID:      "lob-pub-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`),
		SecretGroup: 1,
		Keywords: []string{
			"test_pub",
			"live_pub",
			"_pub",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("lob", "test_pub_"+secrets.NewSecret(hex("31"))),
	}
	return validate(r, tps, nil)
}

func LobAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Lob API Key",
		RuleID:      "lob-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`),
		Keywords: []string{
			"test_",
			"live_",
		},
		SecretGroup: 1,
	}

	// validate
	tps := []string{
		generateSampleSecret("lob", "test_"+secrets.NewSecret(hex("35"))),
	}
	return validate(r, tps, nil)
}
