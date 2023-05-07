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
        Regex: regexp.MustCompile("(sk-)[a-zA-Z0-9]{48}"),
        Keywords: []string{"sk-",},
    }

    // validate
    tps := []string{
        generateSampleSecret("sk-", secrets.NewSecret(alphaNumeric("48"))),
    }
    return validate(r, tps, nil)
}
