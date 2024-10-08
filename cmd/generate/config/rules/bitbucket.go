package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:      "bitbucket-client-id",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
		RuleID:      "bitbucket-client-secret",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumericExtended("64"), true),

		Keywords: []string{"bitbucket"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}
