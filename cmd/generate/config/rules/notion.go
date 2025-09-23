package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Notion() *config.Rule {
	// Define the identifiers that match the Keywords
	identifiers := []string{"ntn_"}

	// Define the regex pattern for Notion API token
	secretRegex := `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`

	regex := utils.GenerateUniqueTokenRegex(secretRegex, false)

	r := config.Rule{
		Description: "Notion API token",
		RuleID:      "notion-api-token",
		Regex:       regex,
		Entropy:     4,
		Keywords:    identifiers,
	}

	// validate
	tps := []string{
		"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",
		"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",
		"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",
	}

	fps := []string{
		"ntn_12345678901",
		"ntn_123456789012345678901234567890123456789012345678901234567890",
		"ntn_12345678901abc",
	}

	return utils.Validate(r, tps, fps)
}
