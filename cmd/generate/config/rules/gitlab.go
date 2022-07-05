package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Gitlab() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "GitLab Personal Access Token",
		RuleID:      "gitlab-pat",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"glpat-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("gitlab", "glpat-"+secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}
