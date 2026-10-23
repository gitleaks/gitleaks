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
		Description: "Detected an OpenRouter API Key, which may compromise LLM gateway access and expose billed model usage to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-or-v1-[0-9a-f]{64}`, false),
		Keywords: []string{
			"sk-or-v1-",
		},
	}

	// validate
	tps := []string{
		// Valid API key example
		utils.GenerateSampleSecret("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("64"))),
		// Generate additional random test key
		utils.GenerateSampleSecret("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("64"))),
	}

	fps := []string{
		// Too short key (missing characters)
		utils.GenerateSampleSecret("openrouter", "sk-or-v1-"+secrets.NewSecret(utils.Hex("32"))),
		// Wrong version prefix
		utils.GenerateSampleSecret("openrouter", "sk-or-v2-"+secrets.NewSecret(utils.Hex("64"))),
		// Uppercase hex is not valid for OpenRouter keys
		utils.GenerateSampleSecret("openrouter", "sk-or-v1-"+secrets.NewSecret("[0-9A-F]{64}")),
	}

	return utils.Validate(r, tps, fps)
}
