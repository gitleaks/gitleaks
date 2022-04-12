package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func NewRelicUserID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-key",
		Description: "New Relic user API Key",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRAK-[a-z0-9]{27}`),
		SecretGroup: 1,
		Keywords: []string{
			"NRAK",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", "NRAK-"+sampleAlphaNumeric27Token),
	}
	return validate(r, tps)
}

func NewRelicUserKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-id",
		Description: "New Relic user API ID",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, alphaNumeric64),
		SecretGroup: 1,
		Keywords: []string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", sampleAlphaNumeric64Token),
	}
	return validate(r, tps)
}

func NewRelicBrowserAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-browser-api-token",
		Description: "New Relic ingest browser API token",
		Regex: generateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRJS-[a-f0-9]{19}`),
		SecretGroup: 1,
		Keywords: []string{
			"NRJS-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("new-relic", "NRJS-"+sampleHex19Token),
	}
	return validate(r, tps)
}
