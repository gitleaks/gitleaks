package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenAI() *config.Rule {
    // Define Rule
    r := config.Rule{
        Description: "Open AI token",
        RuleID:      "open-ai-token",
        Regex: generateUniqueTokenRegex(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`),
        SecretGroup: 1,
        Keywords: []string{
            "sk-", 
            "T3BlbkFJ",
        },
    }

    // validate
    tps := []string{
        generateSampleSecret("OpenAI", "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"),  //gitleaks: allow
    }
    return validate(r, tps, nil)
}
