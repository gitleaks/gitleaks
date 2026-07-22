package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://docs.x.ai/docs#getting-an-api-key
func XAIAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "xai-api-key",
		Description: "Detected an xAI (Grok) API key, which could allow unauthorized access to xAI language model services and incur unexpected charges.",
		Regex:       utils.GenerateUniqueTokenRegex(`xai-[A-Za-z0-9]{80}`, false),
		Entropy:     4,
		Keywords:    []string{"xai-"},
	}

	tps := utils.GenerateSampleSecrets("xai", "xai-"+secrets.NewSecret(utils.AlphaNumeric("80")))
	fps := []string{
		// placeholder / template value, not a real key
		`XAI_API_KEY=xai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		// too short - 40 chars instead of 80
		`XAI_API_KEY=xai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}
