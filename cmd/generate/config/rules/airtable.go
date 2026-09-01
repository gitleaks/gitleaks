package rules

import (
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
	// Airtable Personal Access Tokens always start with the literal prefix "pat"
	// followed by 14 alphanumeric characters, a dot, and 64 hex digits.
	// The regex is a self-signaling unique-token pattern; it does not contain
	// the word "airtable".  The keyword must therefore be a substring that the
	// regex guarantees — i.e. the token prefix "pat" — so the prefilter never
	// silently drops a bare token that has no "airtable" word nearby.
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-personnal-access-token",
		Regex:       utils.GenerateUniqueTokenRegex(`pat[[:alnum:]]{14}\.[a-f0-9]{64}`, false),
		Keywords:    []string{"pat"},
	}

	// validate — include a bare token with no "airtable" context to prove the
	// prefilter fires on the "pat" prefix alone.
	secret := "pat" + secrets.NewSecret(utils.AlphaNumeric("14")+"\\."+utils.Hex("64"))
	tps := []string{
		secret,
		`token = "` + secret + `"`,
		`Authorization: Bearer ` + secret,
	}
	return utils.Validate(r, tps, nil)
}
