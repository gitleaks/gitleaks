package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DefinedNetworkingAPIToken() *config.Rule {
	// Define Rule
	r := config.Rule{
		// Human redable description of the rule
		Description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",

		// Unique ID for the rule
		RuleID: "defined-networking-api-token",

		// Regex used for detecting secrets. See regex section below for more details
		Regex: utils.GenerateSemiGenericRegex([]string{"dnkey"}, `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`, true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: []string{"dnkey"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("dnkey", "dnkey-"+secrets.NewSecret(utils.AlphaNumericExtended("26"))+"-"+secrets.NewSecret(utils.AlphaNumericExtended("52")))
	return utils.Validate(r, tps, nil)
}
