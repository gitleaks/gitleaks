package rules

import (
	"fmt"

	"github.com/gitleaks/gitleaks/v8/cmd/generate/secrets"
	"github.com/gitleaks/gitleaks/v8/config"
)

func Authress() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Authress Service Client Access Key",
		RuleID:      "authress-service-client-access-key",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`(?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc_[a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}`),
		Keywords:    []string{"sc_", "ext_", "scauth_", "authress_"},
	}

	// validate
	// https://authress.io/knowledge-base/docs/authorization/service-clients/secrets-scanning/#1-detection
	service_client_id := "sc_" + alphaNumeric("10")
	access_key_id := alphaNumeric("4")
	account_id := "acc_" + alphaNumeric("10")
	signature_key := alphaNumericExtendedShort("40")

	tps := []string{
		generateSampleSecret("authress", secrets.NewSecret(fmt.Sprintf(`%s\.%s\.%s\.%s`, service_client_id, access_key_id, account_id, signature_key))),
	}
	return validate(r, tps, nil)
}
