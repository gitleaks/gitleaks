package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FlickrAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flickr-access-token",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		Regex:       generateSemiGenericRegex([]string{"flickr"}, alphaNumeric("32"), true),

		Keywords: []string{
			"flickr",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("flickr", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
