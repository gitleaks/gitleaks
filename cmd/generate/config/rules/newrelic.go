package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NewRelicUserID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-key",
		Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRAK-[a-z0-9]{27}`, true),

		Keywords: []string{
			"NRAK",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", "NRAK-"+secrets.NewSecret(alphaNumeric("27"))),
	}
	return validate(r, tps, nil)
}

func NewRelicUserKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-id",
		Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, alphaNumeric("64"), true),

		Keywords: []string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}

func NewRelicBrowserAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-browser-api-token",
		Description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRJS-[a-f0-9]{19}`, true),

		Keywords: []string{
			"NRJS-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", "NRJS-"+secrets.NewSecret(hex("19"))),
	}
	return validate(r, tps, nil)
}

func NewRelicInsertKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-insert-key",
		Description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRII-[a-z0-9-]{32}`, true),

		Keywords: []string{
			"NRII-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", "NRII-"+secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
