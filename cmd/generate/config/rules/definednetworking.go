package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DefinedNetworkingAPIToken() *config.Rule {
	// Define Rule
	r := config.Rule{
		// Human redable description of the rule
		Description: "Defined Networking API token",

		// Unique ID for the rule
		RuleID: "defined-networking-api-token",

		// Regex capture group for the actual secret
		SecretGroup: 1,

		// Regex used for detecting secrets. See regex section below for more details
		Regex: generateSemiGenericRegex([]string{"dnkey"}, `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`, true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: []string{"dnkey"},
	}

	// validate
	tps := []string{
		generateSampleSecret("dnkey", "dnkey-"+secrets.NewSecret(alphaNumericExtended("26"))+"-"+secrets.NewSecret(alphaNumericExtended("52"))),
	}
	return validate(r, tps, nil)
}
