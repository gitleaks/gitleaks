package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TwitterAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter-api-key",
		RuleID:      "Twitter API Key",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("25")),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret(alphaNumeric("25"))),
	}
	return validate(r, tps, nil)
}

func TwitterAPISecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter-api-secret",
		RuleID:      "Twitter API Secret",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("50")),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret(alphaNumeric("50"))),
	}
	return validate(r, tps, nil)
}

func TwitterBearerToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter-bearer-token",
		RuleID:      "Twitter Bearer Token",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, "A{22}[a-zA-Z0-9%]{80,100}"),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret("A{22}[a-zA-Z0-9%]{80,100}")),
	}
	return validate(r, tps, nil)
}

func TwitterAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter-access-token",
		RuleID:      "Twitter access token",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, "[0-9]{15,25}-[a-zA-Z0-9]{20,40}"),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret("[0-9]{15,25}-[a-zA-Z0-9]{20,40}")),
	}
	return validate(r, tps, nil)
}

func TwitterAccessSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter-access-secret",
		RuleID:      "Twitter access secret",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("45")),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret(alphaNumeric("45"))),
	}
	return validate(r, tps, nil)
}
