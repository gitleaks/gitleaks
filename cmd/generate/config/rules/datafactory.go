package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func AzureDataFactory() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Data Factory Self-Hosted Integration Runtime Key, which may compromise big data analytics platforms and sensitive data processing.",
		RuleID:      "datafactory-shir-token",
		// SHIR Key format: IR@{GUID}@{string_azure_resource_name}@{string_azure_resource_location}@{string_base64}
		Regex:    generateUniqueTokenRegex(`IR@[0-9a-zA-Z-]{36}@(.*?)@[0-9a-zA-Z\-=]*@[A-Za-z0-9+\/=]{44}`, false),
		Keywords: []string{"IR@"},
	}

	// validate
	tps := []string{
		"IR@40040abc-b2f2-8tyg-ab39-90a490zzzaae@adf-myapp-001@we@uUY/w9WdKTdAWWPDMrEEWdAEZIgeXlrO51GtVUR1/BE=",
	}
	return validate(r, tps, nil)
}
