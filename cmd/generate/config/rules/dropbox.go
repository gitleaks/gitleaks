package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DropBoxAPISecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Dropbox API secret",
		RuleID:      "dropbox-api-token",
		Regex:       generateSemiGenericRegex([]string{"dropbox"}, alphaNumeric("15")),
		SecretGroup: 1,
		Keywords:    []string{"dropbox"},
	}

	// validate
	tps := []string{
		generateSampleSecret("dropbox", secrets.NewSecret(alphaNumeric("15"))),
	}
	return validate(r, tps, nil)
}

func DropBoxShortLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-short-lived-api-token",
		Description: "Dropbox short lived API token",
		Regex:       generateSemiGenericRegex([]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}

func DropBoxLongLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-long-lived-api-token",
		Description: "Dropbox long lived API token",
		Regex:       generateSemiGenericRegex([]string{"dropbox"}, `[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}
