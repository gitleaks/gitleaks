package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Atlassian() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.",
		RuleID:      "atlassian-api-token",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"atlassian", "confluence", "jira"}, utils.AlphaNumeric("24"), true),
		Keywords: []string{"atlassian", "confluence", "jira"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("atlassian", secrets.NewSecret(utils.AlphaNumeric("24"))),
		utils.GenerateSampleSecret("confluence", secrets.NewSecret(utils.AlphaNumeric("24"))),
	}
	return utils.Validate(r, tps, nil)
}
