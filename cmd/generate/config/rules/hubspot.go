package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HubSpot() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "hubspot-api-key",
		Description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		Regex: utils.GenerateSemiGenericRegex([]string{"hubspot"},
			`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, true),
		Entropy:  3,
		Keywords: []string{"hubspot"},
	}

	// validate
	tps := []string{
		`const hubspotKey = "b7bc6633-e1fc-431e-b812-4231e2ffdd2e"`, // gitleaks:allow
	}
	fps := []string{
		`const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
