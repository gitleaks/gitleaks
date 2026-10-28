package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ZhipuApiKey() *config.Rule {
	// define rule
	// Zhipu AI / Z.ai (BigModel) keys authenticate against the GLM model APIs.
	// They consist of a 32-character hex id and a 16-character secret joined
	// by a period, e.g. "0123...cdef.AbCd012345678901".
	r := config.Rule{
		RuleID:      "zhipu-api-key",
		Description: "Identified a Zhipu AI (Z.ai) API Key, which may compromise GLM model integrations and expose paid AI quota to unauthorized access.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"zhipu", "bigmodel", "glm", "zai"},
			`[0-9a-f]{32}\.[a-zA-Z0-9]{16}`, true),
		Keywords: []string{
			"zhipu",
			"bigmodel",
			"glm",
			"zai",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("zhipu", secrets.NewSecret(`[0-9a-f]{32}\.[a-zA-Z0-9]{16}`)),
		utils.GenerateSampleSecret("bigmodel", secrets.NewSecret(`[0-9a-f]{32}\.[a-zA-Z0-9]{16}`)),
		`ZHIPU_API_KEY = "1234567890abcdef1234567890abcdef.AbCdEf0123456789"`,
	}
	fps := []string{
		// Right structure but no provider keyword nearby
		`token = "1234567890abcdef1234567890abcdef.AbCdEf0123456789"`,
		// Wrong id length
		`zhipu_api_key = "1234567890abcdef.AbCdEf0123456789"`,
	}

	return utils.Validate(r, tps, fps)
}
