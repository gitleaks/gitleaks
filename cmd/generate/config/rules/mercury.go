package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MercuryAPIToken() *config.Rule {
	// Define Rule
	r := config.Rule{
		Description: "Mercury API Token",
		RuleID:      "mercury-api-token",
		Regex:       regexp.MustCompile(`(secret-token:)?mercury_[A-Za-z0-9_-]+_yrucrem`),
		Keywords:    []string{"mercury"},
	}

	// validate
	tps := []string{
		generateSampleSecret("mercury", "secret-token:mercury_production_rma_"+secrets.NewSecret(alphaNumeric("45"))+"_yrucrem"),
	}
	return validate(r, tps, nil)
}
