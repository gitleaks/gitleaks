package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func AWSSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "aws-secret-access-key",
		Description: "TODO: write proper description",
		Regex:       utils.GenerateUniqueTokenRegex(`[A-Za-z0-9/+=]{40}`, false),
		Entropy:     3,
		IsSubRule:  true,
		Allowlists: []config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`.+EXAMPLE$`),
				},
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("AWSSecret", "lbqlNh3FW5/3AwnBoWsYIJam9w2Us4ZOH5Un8RyR") // gitleaks:allow
	fps := []string{
		"lbqlNh3FW5/3AwnBoWsYIJam9w2Us4ZOH5Un8RyRX", // wrong length
		"lbqlN'3FW5/3AwnBoWsYIJam9w2Us4ZOH5Un8RyR",	 // invalid character
	}
	return utils.Validate(r, tps, fps)
}
