package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FreshbooksAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "freshbooks-access-token",
		Description: "Freshbooks Access Token",
		Regex:       generateSemiGenericRegex([]string{"freshbooks"}, alphaNumeric("64")),
		SecretGroup: 1,
		Keywords: []string{
			"freshbooks",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("freshbooks", secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
