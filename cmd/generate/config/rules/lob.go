package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LobPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
		RuleID:      "lob-pub-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`, true),

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
		Description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
		RuleID:      "lob-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`, true),
		Keywords: []string{
			"test_",
			"live_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("lob", "test_"+secrets.NewSecret(hex("35"))),
	}
	return validate(r, tps, nil)
}
