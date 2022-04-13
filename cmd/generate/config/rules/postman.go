package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func PostManAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "postman-api-token",
		Description: "Postman API token",
		Regex:       generateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
		SecretGroup: 1,
		Keywords: []string{
			"PMAK-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("postmanAPItoken", "PMAK-"+sampleHex24Token+"-"+sampleHex34Token),
	}
	return validate(r, tps)
}
