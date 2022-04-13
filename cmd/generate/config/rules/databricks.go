package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func Databricks() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Databricks API token",
		RuleID:      "databricks-api-token",
		Regex:       regexp.MustCompile(`dapi[a-h0-9]{32}`),
		Keywords:    []string{"dapi"},
	}

	// validate
	tps := []string{
		generateSampleSecret("databricks", "dapi"+sampleHex32Token),
	}
	return validate(r, tps)
}
