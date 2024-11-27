package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// TODO this one could probably use some work
func GCPServiceAccount() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\"type\": \"service_account\"`),
		Keywords:    []string{`\"type\": \"service_account\"`},
	}

	// validate
	tps := []string{
		`"type": "service_account"`,
	}
	return utils.Validate(r, tps, nil)
}

func GCPAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gcp-api-key",
		Description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIza[\w-]{35}`, false),
		Entropy:     3.0,
		Keywords: []string{
			"AIza",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gcp", secrets.NewSecret(`AIza[\w-]{35}`))
	tps = append(tps,
		// non-word character at end
		`AIzaSyNHxIf32IQ1a1yjl3ZJIqKZqzLAK1XhDk-`, // gitleaks:allow
	)
	fps := []string{
		`GWw4hjABFzZCGiRpmlDyDdo87Jn9BN9THUA47muVRNunLxsa82tMAdvmrhOqNkRKiYMEAFbTJAIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDq`, // text boundary start
		`AIzaTesb6Tscfcni8vIpWZqNCXFDFslJtVSvFDqabcd123`,                                                                   // text boundary end
		`apiKey: "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,                                                                // not enough entropy
		`AIZASYCO2CXRMC9ELSKLHLHRMBSWDEVEDZTLO2O`,                                                                          // incorrect case
	}
	return utils.Validate(r, tps, fps)
}
