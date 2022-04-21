package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Contentful delivery API token",
		RuleID:      "contentful-delivery-api-token",
		Regex: generateSemiGenericRegex([]string{"contentful"},
			alphaNumericExtended("43")),
		SecretGroup: 1,
		Keywords:    []string{"contentful"},
	}

	// validate
	tps := []string{
		generateSampleSecret("contentful", secrets.NewSecret(alphaNumeric("43"))),
	}
	return validate(r, tps, nil)
}
