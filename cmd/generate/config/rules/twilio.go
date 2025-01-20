package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Twilio() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "twilio-api-key",
		Description: "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.",
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Entropy:     3,
		Keywords:    []string{"SK"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("twilio", "SK"+secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}
