package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func AnsibleVaultToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "CSCAN0270 - Found Azure Subscription Token Cache.",
		RuleID:      "ansible-vault-token",
		SecretGroup: 1,
		Regex: generateUniqueTokenRegex(`\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256[\r\n]+[0-9]+`),
	}

	// validate
	tps := []string{
		generateSampleSecret("ansible-vault-token",
			`$ANSIBLE_VAULT;1.0;AES256\n1145141919810`),
	}
	return validate(r, tps, nil)
}


