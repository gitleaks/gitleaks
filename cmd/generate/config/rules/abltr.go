package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AbltrAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "abltr-api-key",
		Description: "Detected an abltr API key, which could allow unauthorized access to hosted inference models and services.",
		Regex:       regexp.MustCompile(`\b(abltr-ai-[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`),
		Keywords:    []string{"abltr-ai-"},
		SecretGroup: 1,
	}

	// validate
	tps := utils.GenerateSampleSecrets("abltr", "abltr-ai-46c2d93b597498cfa104c8a7f63ab2fd834bf0c2a23ac4ea40eedaa61d8beb50")
	fps := []string{
		"ABLTR_API_KEY=abltr-ai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"abltr-ai-1be08f189bd12f42880fd2c8450d44f0",
	}
	return utils.Validate(r, tps, fps)
}
