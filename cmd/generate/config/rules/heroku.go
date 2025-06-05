package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Heroku() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "heroku-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"heroku"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{"heroku"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("heroku", secrets.NewSecret(utils.Hex8_4_4_4_12()))
	tps = append(tps,
		`const HEROKU_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		`heroku_api_key = "832d2129-a846-4e27-99f4-7004b6ad53ef"`,   // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}

func HerokuV2() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "heroku-api-key-v2",
		Regex:       utils.GenerateUniqueTokenRegex(`(HRKU-AA[0-9a-zA-Z_-]{58})`, false),
		Entropy:     4,
		Keywords:    []string{"HRKU-AA"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("heroku", secrets.NewSecret(`\b(HRKU-AA[0-9a-zA-Z_-]{58})\b`))
	tps = append(tps,
		`const KEY = "HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u""`,
		`API_Key = "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"`,
	)
	return utils.Validate(r, tps, nil)
}
