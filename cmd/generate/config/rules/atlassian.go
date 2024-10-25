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
		Regex: utils.MergeRegexps(
			utils.GenerateSemiGenericRegex(
				[]string{"atlassian", "confluence", "jira"},
				utils.AlphaNumeric("24"),
				true,
			),
			utils.GenerateSemiGenericRegex(
				[]string{"atlassian", "confluence", "jira"},
				`[A-Za-z0-9_\-=]{192}`,
				false,
			),
		),
		Keywords: []string{"atlassian", "confluence", "jira"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("atlassian", secrets.NewSecret(utils.AlphaNumeric("24"))),
		utils.GenerateSampleSecret("confluence", secrets.NewSecret(utils.AlphaNumeric("24"))),
		utils.GenerateSampleSecret("jira", "ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6"),
	}
	return utils.Validate(r, tps, nil)
}
