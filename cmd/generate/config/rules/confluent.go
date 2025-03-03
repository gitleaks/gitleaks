package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ConfluentSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-secret-key",
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("64"), true),
		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("confluent", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}

func ConfluentAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "confluent-access-token",
		Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("16"), true),

		Keywords: []string{
			"confluent",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("confluent", secrets.NewSecret(utils.AlphaNumeric("16")))
	return utils.Validate(r, tps, nil)
}
