package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func Gitlab() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Gitlab Personal Access Token",
		RuleID:      "gitlab-pat",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"glpat-"},
	}

	// validate
	tps := []string{"gitlabPAT := \"glpat-" + sampleAlphaNumeric20Token + "\""}
	return validate(r, tps)
}
