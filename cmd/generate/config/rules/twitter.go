package rules

import (
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
		"twitterToken := \"" + sampleHex32Token + "aaaa\"",
		"twitterToken := `" + sampleHex32Token + "aaaa`",
	}
	return validate(r, tps)
}
