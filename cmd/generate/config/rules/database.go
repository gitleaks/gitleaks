package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DatabaseCredentials() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a possible database credentials.",
		RuleID:      "database-password",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"db_passw(?:or)?d",
			"database_passw(?:or)?d",
			"pwd",
		}, `[a-zA-Z0-9:;<@=},!$?^]{1,100}`, false),
	}

	// validate
	tps := utils.GenerateSampleSecrets("DB_PASSWORD", secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{20}`))
	tps = append(tps, utils.GenerateSampleSecrets("db_password", secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{6}`))...)
	tps = append(tps, utils.GenerateSampleSecrets("DB_PASSWD", secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{10}`))...)
	tps = append(tps, utils.GenerateSampleSecrets("$DB_PASSWD", secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{15}`))...)
	tps = append(tps, utils.GenerateSampleSecrets("$DB_PASSWORD", secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{50}`))...)
	tps = append(tps,
		`pwd = `+secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{20}`),
		`pwd: `+secrets.NewSecret(`[a-zA-Z0-9:;<@=},!$?^]{50}`),
	)

	fps := []string{
		// readme values
		"DB_PASSWORD=[value]",
		"somepwd=XXXXXXXXXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}
