package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LangsmithApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langsmith-api-key",
		Description: "Detected a LangSmith API Key (personal access token or service key), which may expose LangChain/LangSmith tracing data, prompts, and connected LLM workloads.",
		// LangSmith keys carry a distinctive `lsv2_pt_` (personal access token)
		// or `lsv2_sk_` (service key) prefix followed by a hex body and checksum.
		Regex:   utils.GenerateUniqueTokenRegex(`lsv2_(?:pt|sk)_[a-z0-9]{32}_[a-z0-9]{10}`, false),
		Entropy: 3,
		Keywords: []string{
			"lsv2_pt_",
			"lsv2_sk_",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("langsmith",
			"lsv2_pt_"+secrets.NewSecret(utils.AlphaNumeric("32"))+"_"+secrets.NewSecret(utils.AlphaNumeric("10"))),
		utils.GenerateSampleSecret("langchain",
			"lsv2_sk_"+secrets.NewSecret(utils.AlphaNumeric("32"))+"_"+secrets.NewSecret(utils.AlphaNumeric("10"))),
		`LANGCHAIN_API_KEY=lsv2_pt_` + secrets.NewSecret(utils.AlphaNumeric("32")) + "_" + secrets.NewSecret(utils.AlphaNumeric("10")),
	}
	fps := []string{
		// Legacy `ls__` keys (unsupported since 2024-10-22) and unrelated prefixes.
		`LANGCHAIN_API_KEY=ls__0123456789abcdef0123456789abcdef`,
		// Wrong key type segment.
		`lsv2_xx_0123456789abcdef0123456789abcdef_0123456789`,
	}
	return utils.Validate(r, tps, fps)
}
