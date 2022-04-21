package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Clojars API token",
		RuleID:      "clojars-api-token",
		Regex:       regexp.MustCompile(`(?i)(CLOJARS_)[a-z0-9]{60}`),
		Keywords:    []string{"clojars"},
	}

	// validate
	tps := []string{
		generateSampleSecret("clojars", "CLOJARS_"+secrets.NewSecret(alphaNumeric("60"))),
	}
	return validate(r, tps, nil)
}
