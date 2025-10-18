package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AirtableApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"airtable"}, utils.AlphaNumeric("17"), true),
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", secrets.NewSecret(utils.AlphaNumeric("17")))
	return utils.Validate(r, tps, nil)
}

func AirtablePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-personnal-access-token",
		Regex:       regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", "pat"+secrets.NewSecret(utils.AlphaNumeric("14")+"\\."+utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}
