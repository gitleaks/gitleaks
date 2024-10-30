package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func NewRelicUserID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-key",
		Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRAK-[a-z0-9]{27}`, true),

		Keywords: []string{
			"NRAK",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRAK-"+secrets.NewSecret(utils.AlphaNumeric("27")))
	return utils.Validate(r, tps, nil)
}

func NewRelicUserKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-id",
		Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, utils.AlphaNumeric("64"), true),

		Keywords: []string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}

func NewRelicBrowserAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-browser-api-token",
		Description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRJS-[a-f0-9]{19}`, true),

		Keywords: []string{
			"NRJS-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRJS-"+secrets.NewSecret(utils.Hex("19")))
	return utils.Validate(r, tps, nil)
}

func NewRelicInsertKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-insert-key",
		Description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRII-[a-z0-9-]{32}`, true),

		Keywords: []string{
			"NRII-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRII-"+secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}
