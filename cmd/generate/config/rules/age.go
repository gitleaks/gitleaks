package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AgeSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Age secret key",
		RuleID:      "age secret key",
		Regex:       regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
		Keywords:    []string{"AGE-SECRET-KEY-1"},
	}

	// validate
	tps := []string{
		`apiKey := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
