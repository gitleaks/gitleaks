package rules

import (
    "github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
    "github.com/zricethezav/gitleaks/v8/config"
)

func OnfidoAPIToken() *config.Rule {
    // define rule
    r := config.Rule{
        RuleID:      "onfido-live-api-token",
        Description: "Found an Onfido live API Token posing a risk of unauthorized access to identity verification services data, potentially leading to misuse of PII.",
        Regex:       utils.GenerateUniqueTokenRegex(`(?:api_live(?:_[a-zA-Z]{2})?\.[a-zA-Z0-9-_]{11}\.[-_a-zA-Z0-9]{32})`, true),

        Keywords: []string{
            "onfido",
            "api_live",
            "api_live_ca",
            "api_live_us",
        },
    }

// validate
    tps := []string{utils.GenerateSampleSecret("onfido-live-api-token", "api_live.abc123ABC-_.abc123ABC-_abc123ABC-_abc123ABC-")}
    return utils.Validate(r, tps, nil)
}