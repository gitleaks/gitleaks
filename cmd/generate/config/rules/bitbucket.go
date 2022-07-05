package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Bitbucket Client ID",
		RuleID:      "bitbucket-client-id",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, alphaNumeric("32")),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		generateSampleSecret("bitbucket", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Bitbucket Client Secret",
		RuleID:      "bitbucket-client-secret",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, alphaNumericExtended("64")),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		generateSampleSecret("bitbucket", secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
