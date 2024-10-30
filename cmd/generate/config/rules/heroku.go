package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Heroku() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "heroku-api-key",
		Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"heroku"}, utils.Hex8_4_4_4_12(), true),
		Entropy:     3,
		Keywords:    []string{"heroku"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("heroku", secrets.NewSecret(utils.Hex8_4_4_4_12()))
	tps = append(tps,
		`const HEROKU_KEY = "63866443-cb87-446f-8bf0-80e9be787301"`, // gitleaks:allow
		`heroku_api_key = "832d2129-a846-4e27-99f4-7004b6ad53ef"`,   // gitleaks:allow
	)
	fps := []string{
		`const HEROKU_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
