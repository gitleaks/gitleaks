package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func VaultServiceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "vault-service-token",
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`, false),
		Entropy:     3.5,
		Keywords:    []string{"hvs", "s."},
	}

	// validate
	tps := []string{
		// Old
		utils.GenerateSampleSecret("vault", "s."+secrets.NewSecret(utils.AlphaNumeric("24"))),
		`token: s.ZC9Ecf4M5g9o34Q6RkzGsj0z`,
		// New
		utils.GenerateSampleSecret("vault", "hvs."+secrets.NewSecret(utils.AlphaNumericExtendedShort("90"))),
		`-vaultToken hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg"`, // longer than 100 chars
	}
	fps := []string{
		// Old
		`  credentials: new AWS.SharedIniFileCredentials({ profile: '<YOUR_PROFILE>' })`,                              // word boundary start
		`INFO 4 --- [           main] o.s.b.f.s.DefaultListableBeanFactory     : Overriding bean definition for bean`, // word boundary end
		`s.xxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
		// New
		`hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func VaultBatchToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
		RuleID:      "vault-batch-token",
		Regex:       utils.GenerateUniqueTokenRegex(`hvb\.[a-z0-9_-]{138,212}`, true),
		Keywords:    []string{"hvb"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("vault", "hvb."+secrets.NewSecret(utils.AlphaNumericExtendedShort("138"))),
	}
	return utils.Validate(r, tps, nil)
}
