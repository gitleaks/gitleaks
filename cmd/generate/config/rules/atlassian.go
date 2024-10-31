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
				`[a-zA-Z0-9]{24}`,
				false,
			),
			utils.GenerateUniqueTokenRegex(`ATATT3[A-Za-z0-9_\-=]{186}`, false),
		),
		Entropy:  3.5,
		Keywords: []string{"atlassian", "confluence", "jira", "atatt3"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("atlassian", secrets.NewSecret(utils.AlphaNumeric("24")))
	tps = append(tps, utils.GenerateSampleSecrets("confluence", secrets.NewSecret(utils.AlphaNumeric("24")))...)
	tps = append(tps, utils.GenerateSampleSecrets("jira", secrets.NewSecret(utils.AlphaNumeric("24")))...)
	tps = append(tps, utils.GenerateSampleSecrets("jira", "ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6")...)

	return utils.Validate(r, tps, nil)
}
