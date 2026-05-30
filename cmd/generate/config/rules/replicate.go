package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ReplicateAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "replicate-api-token",
		Description: "Detected a Replicate API token, risking unauthorized access to AI model endpoints.",
		Regex:       utils.GenerateUniqueTokenRegex(`r8_[a-zA-Z0-9]{40}`, true),
		Entropy:     2,
		Keywords:    []string{"r8_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("replicate", "r8_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	return utils.Validate(r, tps, nil)
}
