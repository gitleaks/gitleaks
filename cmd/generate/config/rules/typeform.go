package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Typeform() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "typeform-api-token",
		Description: "Typeform API token",
		Regex: generateSemiGenericRegex([]string{"typeform"},
			`tfp_[a-z0-9\-_\.=]{59}`),
		SecretGroup: 1,
		Keywords: []string{
			"tfp_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("typeformAPIToken", "tfp_"+sampleExtendedAlphaNumeric59Token),
	}
	return validate(r, tps)
}
