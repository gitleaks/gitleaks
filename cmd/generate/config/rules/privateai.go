package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PrivateAIToken() *config.Rule {
	// https://docs.private-ai.com/reference/latest/operation/metrics_metrics_get/
	r := config.Rule{
		RuleID:      "privateai-api-token",
		Description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"private[_-]?ai"}, `[a-z0-9]{32}`, false),
		Entropy:     3,
		Keywords: []string{
			"privateai",
			"private_ai",
			"private-ai",
		},
	}

	// validate
	r.TPs = []string{
		utils.GenerateSampleSecret("privateai", secrets.NewSecret(utils.AlphaNumeric("32"))),
	}
	r.FPs = []string{
		`const privateaiToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`,
	}
	return &r
}
