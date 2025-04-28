package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PerplexityAPIKey() *config.Rule {
	// Define Rule
	r := config.Rule{
		RuleID:      "perplexity-api-key",
		Description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		Regex:       regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
		Keywords:    []string{"pplx-"},
		Entropy:     4.0,
	}

	// validate
	tps := utils.GenerateSampleSecrets("perplexity", "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'")
	fps := []string{
		"PERPLEXITY_API_KEY=pplx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}
