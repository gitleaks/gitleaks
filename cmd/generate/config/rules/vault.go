package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func VaultServiceToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Vault Service Token",
		RuleID:      "vault-service-token",
		Regex:       generateUniqueTokenRegex(`hvs\.[a-z0-9_-]{90,100}`),
		Keywords:    []string{"hvs"},
	}

	// validate
	tps := []string{
		generateSampleSecret("vault", "hvs."+secrets.NewSecret(alphaNumericExtendedShort("90"))),
	}
	return validate(r, tps, nil)
}

func VaultBatchToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Vault Batch Token",
		RuleID:      "vault-batch-token",
		Regex:       generateUniqueTokenRegex(`hvb\.[a-z0-9_-]{138,212}`),
		Keywords:    []string{"hvb"},
	}

	// validate
	tps := []string{
		generateSampleSecret("vault", "hvb."+secrets.NewSecret(alphaNumericExtendedShort("138"))),
	}
	return validate(r, tps, nil)
}
