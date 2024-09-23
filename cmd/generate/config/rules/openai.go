package rules

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenAI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openai-api-key",
		Description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Keywords: []string{
			"T3BlbkFJ",
		},
	}
	r.Verify = createOpenAIVerify(r.RuleID)

	// validate
	tps := []string{
		utils.GenerateSampleSecret("openaiApiKey", "sk-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		utils.GenerateSampleSecret("openaiApiKey", "sk-proj-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, fps)
}

func OpenAIProject() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openai-project-api-key",
		Description: "Found an OpenAI API Project Key, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-proj-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false),
		Keywords: []string{
			"T3BlbkFJ",
		},
	}
	r.Verify = createOpenAIVerify(r.RuleID)

	// validate
	tps := []string{
		utils.GenerateSampleSecret("openaiApiKey", "sk-proj-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		utils.GenerateSampleSecret("openaiApiKey", "sk-"+secrets.NewSecret(utils.AlphaNumeric("20"))+"T3BlbkFJ"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, fps)
}

func createOpenAIVerify(ruleID string) *config.Verify {
	return &config.Verify{
		HTTPVerb: "GET",
		URL:      "https://api.openai.com/v1/me",
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("Bearer ${%s}", ruleID),
			"Content-Type":  "application/json",
		},
		ExpectedStatus: []int{200},
	}
}
