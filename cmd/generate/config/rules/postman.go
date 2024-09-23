package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PostManAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "postman-api-token",
		Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
		Regex:       utils.GenerateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`, false),
		Keywords: []string{
			"PMAK-",
		},
		// https://learning.postman.com/docs/sending-requests/authorization/authorization/
		Verify: &config.Verify{
			HTTPVerb: "GET",
			// TODO: support 'https://api.eu.postman.com'?
			URL: "https://api.getpostman.com/me",
			Headers: map[string]string{
				"X-API-Key": "${postman-api-token}",
			},
			ExpectedStatus: []int{200},
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("postmanAPItoken", "PMAK-"+secrets.NewSecret(utils.Hex("24"))+"-"+secrets.NewSecret(utils.Hex("34"))),
	}
	return utils.Validate(r, tps, nil)
}
