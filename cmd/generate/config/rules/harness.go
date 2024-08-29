package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HarnessApiKey() *config.Rule {
	// Define rule for Harness Personal Access Token (PAT) and Service Account Token (SAT)
	r := config.Rule{
		Description: "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
		RuleID:      "harness-api-key",
		Regex:       regexp.MustCompile(`(?:pat|sat)\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}`),
		Keywords:    []string{"pat.", "sat."},
	}

	// Generate a sample secret for validation
	tps := []string{
		utils.GenerateSampleSecret("harness", "pat."+secrets.NewSecret(utils.AlphaNumeric("22"))+"."+secrets.NewSecret(utils.AlphaNumeric("24"))+"."+secrets.NewSecret(utils.AlphaNumeric("20"))),
		utils.GenerateSampleSecret("harness", "sat."+secrets.NewSecret(utils.AlphaNumeric("22"))+"."+secrets.NewSecret(utils.AlphaNumeric("24"))+"."+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}

	// validate the rule
	return utils.Validate(r, tps, nil)
}
