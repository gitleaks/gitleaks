package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Twilio() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Twilio API Key",
		RuleID:      "twilio-api-key",
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Keywords:    []string{"twilio"},
	}

	// validate
	tps := []string{
		"twilioAPIKey := \"SK" + secrets.NewSecret(hex("32")) + "\"",
	}
	return validate(r, tps, nil)
}
