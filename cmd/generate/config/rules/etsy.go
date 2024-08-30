package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EtsyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:          "etsy-access-token",
		Description:     "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		Regex:           utils.GenerateSemiGenericRegex([]string{"etsy"}, utils.AlphaNumeric("24"), true),
		IdentifierGroup: 1,
		Keywords: []string{
			"etsy",
		},
		Allowlist: config.Allowlist{
			IdentifierStopWords: []string{"getsys", "setsys", "system"},
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("etsy", secrets.NewSecret(utils.AlphaNumeric("24"))),
	}
	fps := []string{
		"sysctl.SetSysctl: sysctlBridgeCallIPTables",
	}
	return utils.Validate(r, tps, fps)
}
