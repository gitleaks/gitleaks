package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Doppler() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		RuleID:      "doppler-api-token",
		Regex:       regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`),
		Keywords:    []string{"doppler"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("doppler", "dp.pt."+secrets.NewSecret(utils.AlphaNumeric("43"))),
	}
	return utils.Validate(r, tps, nil)
}

// TODO add additional doppler formats:
// https://docs.doppler.com/reference/auth-token-formats
