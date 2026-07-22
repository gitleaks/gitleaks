package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Resend() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "resend-api-key",
		Description: "Identified a Resend API key, which could allow unauthorized email sending and access to the Resend account.",
		// Resend keys: literal `re_`, 8 base58 chars, `_`, 24 base58 chars.
		// Base58 alphabet excludes `0`, `O`, `I`, and `l`.
		Regex:   utils.GenerateUniqueTokenRegex(`re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}`, false),
		Entropy: 3,
		Keywords: []string{
			"re_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets(
		"resend",
		"re_"+secrets.NewSecret(`[1-9A-HJ-NP-Za-km-z]{8}`)+"_"+secrets.NewSecret(`[1-9A-HJ-NP-Za-km-z]{24}`),
	)
	tps = append(tps,
		`resendApiKey := "re_1234abcd_aBcDeFgHiJkLmNoPqRsTuVwX"`,
	)

	fps := []string{
		// `0` is not in the base58 alphabet.
		`resendApiKey := "re_0234abcd_aBcDeFgHiJkLmNoPqRsTuVwX"`,
		// `O` is not in the base58 alphabet.
		`resendApiKey := "re_1234abcd_OBcDeFgHiJkLmNoPqRsTuVwX"`,
		// `I` is not in the base58 alphabet.
		`resendApiKey := "re_I234abcd_aBcDeFgHiJkLmNoPqRsTuVwX"`,
		// `l` is not in the base58 alphabet.
		`resendApiKey := "re_1234abcl_aBcDeFgHiJkLmNoPqRsTuVwX"`,
		// First segment is only 7 chars.
		`resendApiKey := "re_1234abc_aBcDeFgHiJkLmNoPqRsTuVwX"`,
		// Missing the `_` separator between segments.
		`resendApiKey := "re_1234abcdaBcDeFgHiJkLmNoPqRsTuVwX"`,
	}
	return utils.Validate(r, tps, fps)
}
