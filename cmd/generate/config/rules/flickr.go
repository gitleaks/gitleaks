package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FlickrAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flickr-access-token",
		Description: "Flickr Access Token",
		Regex:       generateSemiGenericRegex([]string{"flickr"}, alphaNumeric("32")),
		SecretGroup: 1,
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
