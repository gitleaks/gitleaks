package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Dynatrace() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Dynatrace API token",
		RuleID:      "dynatrace-api-token",
		Regex:       regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
		Keywords:    []string{"dynatrace"},
	}

	// validate
	tps := []string{
		generateSampleSecret("dynatrace", "dt0c01."+secrets.NewSecret(alphaNumeric("24"))+"."+secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
