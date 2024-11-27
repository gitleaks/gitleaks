package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DropBoxAPISecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
		RuleID:      "dropbox-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"dropbox"}, utils.AlphaNumeric("15"), true),

		Keywords: []string{"dropbox"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("dropbox", secrets.NewSecret(utils.AlphaNumeric("15")))
	return utils.Validate(r, tps, nil)
}

func DropBoxShortLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-short-lived-api-token",
		Description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`, true),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}

func DropBoxLongLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-long-lived-api-token",
		Description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"dropbox"}, `[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`, true),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}
