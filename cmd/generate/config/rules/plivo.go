package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlivoAuthID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Plivo Auth ID",
		RuleID:      "plivo-auth-id",
		Regex:       generateSemiGenericRegex([]string{"plivo", "plivo_auth_id"}, "[SM]{1}A[0-9A-Za-z]{18}"),
		SecretGroup: 1,
		Keywords:    []string{"plivo", "plivo_auth_id"},
	}

	// validate
	tps := []string{
		generateSampleSecret("PLIVO_AUTH_ID", "MAWHJMELDNYIHEMCIWLD"),
		generateSampleSecret("PLIVO_AUTH_ID", "SAWHJMELDNYIHEMCIWLD"),
		generateSampleSecret("plivo_auth_id", "MAWHJMELDNYIHEMCIWLD"),
		generateSampleSecret("plivo_auth_id", "SAWHJMELDNYIHEMCIWLD"),
		generateSampleSecret("plivo", "MAWHJMELDNYIHEMCIWLD"),
		generateSampleSecret("plivo", "SAWHJMELDNYIHEMCIWLD"),
	}
	return validate(r, tps, nil)
}
