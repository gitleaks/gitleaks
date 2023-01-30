package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Plivo() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Plivo Auth ID",
		RuleID:      "plivo-auth-id",
		Regex:       regexp.MustCompile(`[SM]{1}A[0-9A-Za-z]{18}`),
		Keywords:    []string{"plivo"},
	}

	// validate
	tps := []string{
		"plivoAuthID := \"MA" + secrets.NewSecret(hex("18")) + "\"",
	}
	return validate(r, tps, nil)
}
