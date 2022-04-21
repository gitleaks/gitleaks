package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FrameIO() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Frame.io API token",
		RuleID:      "frameio-api-token",
		Regex:       regexp.MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`),
		Keywords:    []string{"fio-u-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("frameio", "fio-u-"+secrets.NewSecret(alphaNumericExtended("64"))),
	}
	return validate(r, tps, nil)
}
