package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LangSmithAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a LangSmith API key, which may expose traces, datasets and prompts in the workspace.",
		RuleID:      "langsmith-api-key",
		Regex:       regexp.MustCompile(`\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b`),
		Keywords:    []string{"lsv2_pt_", "lsv2_sk_"},
	}

	// validate
	tps := []string{
		"LANGSMITH_API_KEY=" + secrets.NewSecret("lsv2_pt_[a-f0-9]{32}_[a-f0-9]{10}"),
		"LANGSMITH_API_KEY=" + secrets.NewSecret("lsv2_sk_[a-f0-9]{32}_[a-f0-9]{10}"),
	}
	fps := []string{
		// Tracing keys use the lsv2_tr_ prefix and a different shape; not covered here.
		"LANGSMITH_API_KEY=lsv2_pt_0123456789abcdef",
	}
	return utils.Validate(r, tps, fps)
}
