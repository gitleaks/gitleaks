package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Dynatrace() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		RuleID:      "dynatrace-api-token",
		Regex:       regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
		Keywords:    []string{"dynatrace"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("dynatrace", "dt0c01."+secrets.NewSecret(utils.AlphaNumeric("24"))+"."+secrets.NewSecret(utils.AlphaNumeric("64"))),
	}
	return utils.Validate(r, tps, nil)
}
