package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenRouterApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openrouter-api-key",
		Description: "Detected an OpenRouter API Key, posing a risk of unauthorized access to AI models and budget consumption.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-or(-v\d+)?-[a-f0-9]{64}`, false),
		Keywords: []string{
			"sk-or",
		},
	}

	// validate
	tps := []string{
		// Valid API key examples
		"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",
		"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",
		"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",
		// Generate additional random test keys
		utils.GenerateSampleSecret("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("64"))),
	}

	fps := []string{
		// Too short key (missing characters)
		"sk-or-v1-faae9eb62e12ed4c6a3680ac0805d49cfb8f6a0c91bf405abd1c32f5e7c0916",
		// Wrong suffix
		"sk-ant-v1-faae9eb62e12ed4c6a3680ac0805d49cfb8f6a0c91bf405abd1c32f5e7c0916f",
		// Non-hexadecimal characters (contains 'g')
		"sk-or-v1-gaae9eb62e12ed4c6a3680ac0805d49cfb8f6a0c91bf405abd1c32f5e7c0916f",
	}

	return utils.Validate(r, tps, fps)
}
