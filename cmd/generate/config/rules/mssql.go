package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// MSSQLDatabaseCredentials generates a rule for detecting exposure of MSSQL database credentials.
func MSSQLDatabaseCredentials() *config.Rule {
	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Detects exposure of MSSQL database credentials",

		// Unique ID for the rule
		RuleID: "mssql-database-credentials",

		// Regex used for detecting secrets
		Regex: regexp.MustCompile(
			`Password=[^;]+`),

		// Keywords used for string matching on fragments (pre-filter)
		Keywords: []string{"MSSQL", "credentials"},
	}

	// Validate rule
	tps := []string{
		// Example secrets that match the rule
		"Password=mySecurePassword123;",
	}
	return validate(r, tps, nil)
}
