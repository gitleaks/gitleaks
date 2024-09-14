package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Doppler() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		RuleID:      "doppler-api-token",
		Regex:       regexp.MustCompile(`(dp\.pt\.)(?i)[a-z0-9]{43}`),
		Keywords:    []string{"doppler"},
	}

	// validate
	tps := []string{
		generateSampleSecret("doppler", "dp.pt."+secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}

// TODO add additional doppler formats:
// https://docs.doppler.com/reference/auth-token-formats
