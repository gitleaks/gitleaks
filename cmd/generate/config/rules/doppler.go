package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Doppler() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "doppler-api-token",
		Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		Regex:       regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`),
		Entropy:     2,
		Keywords:    []string{`dp.pt.`},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("doppler", "dp.pt."+secrets.NewSecret(utils.AlphaNumeric("43")))
	return &r
}

// TODO add additional doppler formats:
// https://docs.doppler.com/reference/auth-token-formats
