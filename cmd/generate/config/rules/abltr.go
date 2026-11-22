package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AbltrAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "abltr-api-key",
		Description: "Detected an abltr API key, which could allow unauthorized access to hosted inference models and services.",
		Regex:       utils.GenerateUniqueTokenRegex(`abltr-ai-[a-f0-9]{64}`, false),
		Keywords:    []string{"abltr-ai-"},
	}

	// validate
	tps := []string{
		"abltr-ai-46c2d93b597498cfa104c8a7f63ab2fd834bf0c2a23ac4ea40eedaa61d8beb50",
		"ABLTR_API_KEY=abltr-ai-9f1c0e7a4b3d26c58a1e0f7d4b3c2a196e8d5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
	}
	fps := []string{
		// too short
		"abltr-ai-1be08f189bd12f42880fd2c8450d44f0",
		// non-hex placeholder
		"abltr-ai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		// uppercase hex is not the documented format
		"abltr-ai-46C2D93B597498CFA104C8A7F63AB2FD834BF0C2A23AC4EA40EEDAA61D8BEB50",
	}
	return utils.Validate(r, tps, fps)
}
