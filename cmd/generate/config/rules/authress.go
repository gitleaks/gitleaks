package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Authress() *config.Rule {
	// Rule Definition
	// (Note: When changes are made to this, rerun `go generate ./...` and commit the config/gitleaks.toml file
	r := config.Rule{
		RuleID:      "authress-service-client-access-key",
		Description: "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}`, false),
		Entropy:     2,
		Keywords:    []string{"sc_", "ext_", "scauth_", "authress_"},
	}

	// validate
	// https://authress.io/knowledge-base/docs/authorization/service-clients/secrets-scanning/#1-detection
	service_client_id := "sc_" + utils.AlphaNumeric("10")
	access_key_id := utils.AlphaNumeric("4")
	account_id := "acc_" + utils.AlphaNumeric("10")
	signature_key := utils.AlphaNumericExtendedShort("40")

	tps := utils.GenerateSampleSecrets("authress", secrets.NewSecret(fmt.Sprintf(`%s\.%s\.%s\.%s`, service_client_id, access_key_id, account_id, signature_key)))
	return utils.Validate(r, tps, nil)
}
