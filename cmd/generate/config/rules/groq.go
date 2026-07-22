package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://console.groq.com/keys
func GroqAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "groq-api-key",
		Description: "Detected a Groq API key, which could allow unauthorized access to Groq AI inference services and result in unexpected charges.",
		Regex:       utils.GenerateUniqueTokenRegex(`gsk_[a-zA-Z0-9]{48}`, false),
		Entropy:     4,
		Keywords:    []string{"gsk_"},
	}

	tps := utils.GenerateSampleSecrets("groq", "gsk_"+secrets.NewSecret(utils.AlphaNumeric("48")))
	fps := []string{
		// placeholder / template value, not a real key
		`GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		// too short
		`GROQ_API_KEY=gsk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
	}
	return utils.Validate(r, tps, fps)
}
