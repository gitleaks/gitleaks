package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Freemius() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Freemius secret key.",
		RuleID:      "freemius-secret-key",
		Regex: utils.GenerateSemiGenericRegex([]string{"secret_key"},
			`sk_[\S]{29}`, false),
		Keywords: []string{"secret_key"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("secret_key", "sk_"+secrets.NewSecret(utils.AlphaNumericExtended("29"))),
	}
	return utils.Validate(r, tps, nil)
}
