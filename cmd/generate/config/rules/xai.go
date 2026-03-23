package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://docs.x.ai/docs/overview#getting-started
func XAIAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "xai-api-key",
		Description: "Detected an xAI API key, which could allow unauthorized access to xAI (Grok) AI services and data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`xai-[A-Za-z0-9]{80}`, false),
		Entropy:     4,
		Keywords:    []string{"xai-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("xai", "xai-"+secrets.NewSecret(utils.AlphaNumeric("80")))
	fps := []string{
		`XAI_API_KEY=xai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // placeholder, not real
	}
	return utils.Validate(r, tps, fps)
}
