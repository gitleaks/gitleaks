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
		Regex:       utils.GenerateUniqueTokenRegex(`sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Entropy:     3,
		Keywords: []string{
			"T3BlbkFJ",
		},
	}

	// validate
	tps := append(utils.GenerateSampleSecrets("openaiApiKey", "sk-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20"))),
		[]string{
			"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",
			"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",
			"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",

			"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",
			"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",
			"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",

			"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",
			"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",
			"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",
		}...)
	return utils.Validate(r, tps, nil)
}
