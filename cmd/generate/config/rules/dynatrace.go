package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Dynatrace() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dynatrace-api-token",
		Description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		Regex:       regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
		Entropy:     4,
		Keywords:    []string{"dt0c01."},
	}

	// validate
	tps := utils.GenerateSampleSecrets("dynatrace", "dt0c01."+secrets.NewSecret(utils.AlphaNumeric("24"))+"."+secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}
