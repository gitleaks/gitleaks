package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Beamer() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
		RuleID:      "beamer-api-token",
		Regex: utils.GenerateSemiGenericRegex([]string{"beamer"},
			`b_[a-z0-9=_\-]{44}`, true),
		Keywords: []string{"beamer"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("beamer", "b_"+secrets.NewSecret(utils.AlphaNumericExtended("44")))
	fps := []string{
		`│   ├── R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu`,
	}
	return utils.Validate(r, tps, fps)
}
