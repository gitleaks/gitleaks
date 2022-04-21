package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Twitter() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter",
		RuleID:      "twitter",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, hex("35,44")),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		"twitterToken := \"" + secrets.NewSecret(hex("36")) + "aaaa\"",
		"twitterToken := `" + secrets.NewSecret(hex("36")) + "aaaa`",
	}
	return validate(r, tps, nil)
}
