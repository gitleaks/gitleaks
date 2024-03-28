package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TwitterAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
		RuleID:      "twitter-api-key",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("25"), true),
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
		Description: "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
		RuleID:      "twitter-api-secret",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("50"), true),
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
		Description: "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
		RuleID:      "twitter-bearer-token",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, "A{22}[a-zA-Z0-9%]{80,100}", true),

		Keywords: []string{"twitter"},
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
		Description: "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
		RuleID:      "twitter-access-token",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, "[0-9]{15,25}-[a-zA-Z0-9]{20,40}", true),
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
		Description: "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
		RuleID:      "twitter-access-secret",
		Regex:       generateSemiGenericRegex([]string{"twitter"}, alphaNumeric("45"), true),
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{
		generateSampleSecret("twitter", secrets.NewSecret(alphaNumeric("45"))),
	}
	return validate(r, tps, nil)
}
