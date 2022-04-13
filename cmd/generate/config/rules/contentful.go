package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Contentful delivery API token",
		RuleID:      "contentful-delivery-api-token",
		Regex: generateSemiGenericRegex([]string{"contentful"},
			`[a-z0-9\-=_]{43}`),
		SecretGroup: 1,
		Keywords:    []string{"contentful"},
	}

	// validate
	tps := []string{
		generateSampleSecret("contentful", sampleExtendedAlphaNumeric43Token),
	}
	return validate(r, tps)
}
