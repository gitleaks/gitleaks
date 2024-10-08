package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FlickrAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flickr-access-token",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"flickr"}, utils.AlphaNumeric("32"), true),

		Keywords: []string{
			"flickr",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("flickr", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
