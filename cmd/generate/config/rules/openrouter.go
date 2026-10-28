package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenRouterAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found an OpenRouter API Key, risking unauthorized access to LLM services and credit consumption.",
		RuleID:      "openrouter-api-key",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-or-v1-[a-f0-9]{64}`, false),
		Entropy:     3.0,
		Keywords: []string{
			"sk-or-v1-",
		},
	}

	// validate dynamically generated sample secret to avoid secret scanning triggers
	tps := utils.GenerateSampleSecrets("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}
