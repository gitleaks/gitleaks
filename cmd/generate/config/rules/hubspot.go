package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func HubSpotAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-api-key",
		Regex: generateSemiGenericRegex(
			[]string{"hubspot"},
			`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			true,
		),

		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}

func HubSpotPrivateAppAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot Private App API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-api-key",
		Regex: generateSemiGenericRegex(
			[]string{"hubspot"},
			`pat-(?:eu|na)/d-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			true,
		),

		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		`const hubspotKey = "pat-eu1-12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}

func HubSpotDeveloperAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a HubSpot Private App API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:      "hubspot-api-key",
		Regex: generateSemiGenericRegex(
			[]string{"hubspot"},
			`(?:eu|na)/d-[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12)`,
			true,
		),

		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		`const hubspotKey = "eu1-1234-ABCD-1234-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
