package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LangGraphApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langgraph-api-key",
		Description: "Detected a LangGraph / LangSmith API Key, which may expose AI agent graph execution traces, state checkpoints, and deployment credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`lsv2_pt_[a-zA-Z0-9]{32}_[a-zA-Z0-9]{8}`, false),
		Keywords: []string{
			"lsv2_pt_",
		},
	}

	// validate
	tps := []string{
		"lsv2_pt_abcdef1234567890abcdef1234567890_12345678",
		utils.GenerateSampleSecret("langgraph", "lsv2_pt_"+secrets.NewSecret(utils.AlphaNumeric("32"))+"_"+secrets.NewSecret(utils.AlphaNumeric("8"))),
	}

	fps := []string{
		// Too short
		"lsv2_pt_abcdef1234567890_12345678",
		// Wrong suffix length
		"lsv2_pt_abcdef1234567890abcdef1234567890_1234",
	}

	return utils.Validate(r, tps, fps)
}
