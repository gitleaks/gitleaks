package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// This rule includes both App Secret and Client Access Token
// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/
func FacebookSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "facebook-secret",
		Description: "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"facebook"}, utils.Hex("32"), true),
		Entropy:     3,
		Keywords:    []string{"facebook"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("facebook", secrets.NewSecret(utils.Hex("32")))
	tps = append(tps,
		`facebook_app_secret = "6dca6432e45d933e13650d1882bd5e69"`,       // gitleaks:allow
		`facebook_client_access_token: 26f5fd13099f2c1331aafb86f6489692`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}

// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/#apptokens
func FacebookAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "facebook-access-token",
		Description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`\d{15,16}(\||%)[0-9a-z\-_]{27,40}`, true),
		Keywords:    []string{"facebook"},
		Entropy:     3,
	}

	// validate
	tps := []string{
		`{"facebook access_token":"911602140448729|AY-lRJZq9BoDLobvAiP25L7RcMg","token_type":"bearer"}`, // gitleaks:allow
		`facebook 1308742762612587|rhoK1cbv0DOU_RTX_87O4MkX7AI`,                                         // gitleaks:allow
		`facebook 1477036645700765|wRPf2v3mt2JfMqCLK8n7oltrEmc`,                                         // gitleaks:allow
	}
	return utils.Validate(r, tps, nil)
}

// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/#pagetokens
func FacebookPageAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "facebook-page-access-token",
		Description: "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex("EAA[MC](?i)[a-z0-9]{100,}", false),
		Entropy:     4,
		Keywords:    []string{"EAAM", "EAAC"},
	}

	// validate
	tps := []string{
		`EAAM9GOnCB9kBO2frzOAWGN2zMnZClQshlWydZCrBNdodesbwimx1mfVJgqZBP5RSpMfUzWhtjTTXHG5I1UlvlwRZCgjm3ZBVGeTYiqAAoxyED6HaUdhpGVNoPUwAuAWWFsi9OvyYBQt22DGLqMIgD7VktuCTTZCWKasz81Q822FPhMTB9VFFyClNzQ0NLZClt9zxpsMMrUZCo1VU1rL3CKavir5QTfBjfCEzHNlWAUDUV2YZD`, // gitleaks:allow
		`EAAM9GOnCB9kBO2zXpAtRBmCrsPPjdA3KeBl4tqsEpcYd09cpjm9MZCBIklZBjIQBKGIJgFwm8IE17G5pipsfRBRBEHMWxvJsL7iHLUouiprxKRQfAagw8BEEDucceqxTiDhVW2IZAQNNbf0d1JhcapAGntx5S1Csm4j0GgZB3DuUfI2HJ9aViTtdfH2vjBy0wtpXm2iamevohGfoF4NgyRHusDLjqy91uYMkfrkc`,          // gitleaks:allow
		`- name: FACEBOOK_TOKEN
		value: "EAACEdEose0cBA1bad3afsf286JZCOV1XmV4NobAXqUXZA7U9F1UaaOdQZABvz73030MJoC3gGoQrE8IEoMl4gFA6MmQadlJQBqtRsgIcIhtelIJOJaew"`, // gitleaks:allow
	}
	fps := []string{
		`eaaaC0b75a9329fded2ffa9a02b47e0117831b82`,
		`"strict-uri-encode@npm:^2.0.0":
  version: 2.0.0
  resolution: "strict-uri-encode@npm:2.0.0"
  checksum: eaac4cf978b6fbd480f1092cab8b233c9b949bcabfc9b598dd79a758f7243c28765ef7639c876fa72940dac687181b35486ea01ff7df3e65ce3848c64822c581
  languageName: node
  linkType: hard`,
	}
	return utils.Validate(r, tps, fps)
}
