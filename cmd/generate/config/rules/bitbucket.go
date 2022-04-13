package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "BitBucket Client ID",
		RuleID:      "bitbucket-client-id",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, alphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		"bitbucket := \"" + sampleAlphaNumeric32Token + "\"",
	}
	return validate(r, tps)
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "BitBucket Client Secret",
		RuleID:      "bitbucket-client-secret",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, extendedAlphaNumeric64),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		"bitbucket := \"" + sampleExtendedAlphaNumeric64Token + "\"",
	}
	return validate(r, tps)
}
