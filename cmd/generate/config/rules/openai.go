package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func OpenAI() *config.Rule {
    // Define Rule
    r := config.Rule{
        Description: "Open AI token",
        RuleID:      "open-ai-token",
        Regex: regexp.MustCompile("(sk-)[a-zA-Z0-9]{20}(T3BlbkFJ)[a-zA-Z0-9]{20}"),
        SecretGroup: 1,
        Keywords: []string{"sk-",},
    }

    // validate
    tps := []string{
        generateSampleSecret("OpenAI", "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"),
    }
    return validate(r, tps, nil)
}
