package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config/rule"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func FrameIO() *rule.Rule {
	// define rule
	r := rule.Rule{
		Description: "Found a Frame.io API token, potentially compromising video collaboration and project management.",
		RuleID:      "frameio-api-token",
		Regex:       regexp.MustCompile(`fio-u-(?i)[a-z0-9\-_=]{64}`),
		Keywords:    []string{"fio-u-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("frameio", "fio-u-"+secrets.NewSecret(utils.AlphaNumericExtended("64")))
	return utils.Validate(r, tps, nil)
}
