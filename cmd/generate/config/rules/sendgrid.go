package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendgrid-api-token",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:       generateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, true),

		Keywords: []string{
			"SG.",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sengridAPIToken", "SG."+secrets.NewSecret(alphaNumericExtended("66"))),
	}
	return validate(r, tps, nil)
}
