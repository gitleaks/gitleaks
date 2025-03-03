package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenAI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openai-api-key",
		Description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Entropy:     3,
		Keywords: []string{
			"T3BlbkFJ",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("openaiApiKey", "sk-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}
