package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PerplexityAPIKey() *config.Rule {
	// Define Rule
	r := config.Rule{
		RuleID:      "perplexity-api-key",
		Description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		Regex:       regexp.MustCompile(`\b(pplx-[\w]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`),
		Keywords:    []string{"pplx"},
		Entropy:     2.0,
	}

	return &r
}
