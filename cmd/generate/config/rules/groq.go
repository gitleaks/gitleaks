package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://console.groq.com/docs/openai
func GroqAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "groq-api-key",
		Description: "Detected a Groq API key, which could allow unauthorized access to Groq AI inference services and incur unexpected costs.",
		Regex:       utils.GenerateUniqueTokenRegex(`gsk_[a-zA-Z0-9]{48}`, false),
		Entropy:     4,
		Keywords:    []string{"gsk_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("groq", "gsk_"+secrets.NewSecret(utils.AlphaNumeric("48")))
	fps := []string{
		`GSK_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // placeholder, not real
	}
	return utils.Validate(r, tps, fps)
}
