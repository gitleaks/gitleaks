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
<<<<<<< HEAD
		Regex:       generateSemiGenericRegex([]string{"confluent"}, `[a-zA-Z-0-9]{64}`),
=======
		Regex:       generateSemiGenericRegex([]string{"confluent"}, alphaNumeric("64")),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
		SecretGroup: 1,
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := []string{
<<<<<<< HEAD
		generateSampleSecret("confluent", secrets.NewSecret(`[a-zA-Z-0-9]{64}`)),
=======
		generateSampleSecret("confluent", secrets.NewSecret(alphaNumeric("64"))),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
	}
	return validate(r, tps, nil)
}

func ConfluentAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-access-token",
		Description: "Confluent Access Token",
<<<<<<< HEAD
		Regex:       generateSemiGenericRegex([]string{"confluent"}, `[a-zA-Z-0-9]{16}`),
=======
		Regex:       generateSemiGenericRegex([]string{"confluent"}, alphaNumeric("16")),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
		SecretGroup: 1,
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := []string{
<<<<<<< HEAD
		generateSampleSecret("confluent", secrets.NewSecret(`[a-zA-Z-0-9]{16}`)),
=======
		generateSampleSecret("confluent", secrets.NewSecret(alphaNumeric("16"))),
>>>>>>> 73a3cf8afbfba27e46a9efbbe29c7f262569d721
	}
	return validate(r, tps, nil)
}
