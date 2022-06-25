package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ConfluentSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-secret-key",
		Description: "Confluent Secret Key",
		Regex:       generateSemiGenericRegex([]string{"confluent"}, `[a-zA-Z-0-9]{64}`),
		SecretGroup: 1,
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("confluent", secrets.NewSecret(`[a-zA-Z-0-9]{64}`)),
	}
	return validate(r, tps, nil)
}

func ConfluentAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-access-token",
		Description: "Confluent Access Token",
		Regex:       generateSemiGenericRegex([]string{"confluent"}, `[a-zA-Z-0-9]{16}`),
		SecretGroup: 1,
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("confluent", secrets.NewSecret(`[a-zA-Z-0-9]{16}`)),
	}
	return validate(r, tps, nil)
}
