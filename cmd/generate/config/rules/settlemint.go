package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SettlemintPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Personal Access Token.",
		RuleID:      "settlemint-personal-access-token",
		Regex:       generateUniqueTokenRegex(`(sm_pat_)[a-zA-Z0-9]+`, false),
		Keywords: []string{
			"sm_pat",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("settlemintToken", "sm_pat_"+secrets.NewSecret(alphaNumeric("16"))),
	}
	fps := []string{"nonMatchingToken := \"" + secrets.NewSecret(alphaNumeric("16")) + "\""}
	return validate(r, tps, fps)
}

func SettlemintApplicationAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Application Access Token.",
		RuleID:      "settlemint-application-access-token",
		Regex:       generateUniqueTokenRegex(`(sm_aat_)[a-zA-Z0-9]+`, false),
		Keywords: []string{
			"sm_aat",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("settlemintToken", "sm_aat_"+secrets.NewSecret(alphaNumeric("16"))),
	}
	fps := []string{"nonMatchingToken := \"" + secrets.NewSecret(alphaNumeric("16")) + "\""}
	return validate(r, tps, fps)
}

func SettlemintServiceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Service Access Token.",
		RuleID:      "settlemint-service-access-token",
		Regex:       generateUniqueTokenRegex(`(sm_sat_)[a-zA-Z0-9]+`, false),
		Keywords: []string{
			"sm_sat",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("settlemintToken", "sm_sat_"+secrets.NewSecret(alphaNumeric("16"))),
	}
	fps := []string{"nonMatchingToken := \"" + secrets.NewSecret(alphaNumeric("16")) + "\""}
	return validate(r, tps, fps)
}
