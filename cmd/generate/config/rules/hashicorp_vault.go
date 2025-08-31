package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func VaultServiceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "vault-service-token",
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`, false),
		Entropy:     3.5,
		Keywords:    []string{"hvs.", "s."},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					// https://github.com/gitleaks/gitleaks/issues/1490#issuecomment-2334166357
					regexp.MustCompile(`s\.[A-Za-z]{24}`),
				},
			},
		},
	}

	// validate
	tps := []string{
		// Old
		utils.GenerateSampleSecret("vault", secrets.NewSecret(`s\.[0-9][a-zA-Z0-9]{23}`)),
		`token: s.ZC9Ecf4M5g9o34Q6RkzGsj0z`,
		// New
		utils.GenerateSampleSecret("vault", secrets.NewSecret(`hvs\.[0-9][\w\-]{89}`)),
		`-vaultToken hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg"`, // longer than 100 chars
	}

	fps := []string{
		// Old
		`  credentials: new AWS.SharedIniFileCredentials({ profile: '<YOUR_PROFILE>' })`,                              // word boundary start
		`INFO 4 --- [           main] o.s.b.f.s.DefaultListableBeanFactory     : Overriding bean definition for bean`, // word boundary end
		`s.xxxxxxxxxxxxxxxxxxxxxxxx`,        // low entropy
		`s.THISSTRINGISALLUPPERCASE`,        // uppercase
		`s.thisstringisalllowercase`,        // lowercase
		`s.AcceptanceTimeoutSeconds `,       // pascal-case
		`s.makeKubeConfigController = args`, // camel-case
		// New
		`hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func VaultBatchToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "vault-batch-token",
		Description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex(`hvb\.[\w-]{138,300}`, false),
		Entropy:     4,
		Keywords:    []string{"hvb."},
	}

	// validate
	tps := utils.GenerateSampleSecrets("vault", "hvb."+secrets.NewSecret(utils.AlphaNumericExtendedShort("138")))
	tps = append(tps, `hvb.AAAAAQJgxDgqsGNorpoOR7hPZ5SU-ynBvCl764jyRP_fnX7WvkdkDzGjbLNGdPdtlY33Als2P36yDZueqzfdGw9RsaTeaYXSH7E4RYSWuRoQ9YRKIw8o7mDDY2ZcT3KOB7RwtW1w1FN2eDqcy_sbCjXPaM1iBVH-mqMSYRmRd2nb5D1SJPeBzIYRqSglLc31wUGN7xEzyrKUczqOKsIcybQA`) // gitleaks:allow
	return utils.Validate(r, tps, nil)
}
