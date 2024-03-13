package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// This rule includes both App Secret and Client Access Token
// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/
func FacebookSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook-secret",
		Regex:       generateSemiGenericRegex([]string{"facebook"}, hex("32"), true),

		Keywords: []string{"facebook"},
	}

	// validate
	tps := []string{
		generateSampleSecret("facebook", secrets.NewSecret(hex("32"))),
		`facebook_app_secret = "6dca6432e45d933e13650d1882bd5e69"`,       // gitleaks:allow
		`facebook_client_access_token: 26f5fd13099f2c1331aafb86f6489692`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}

// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/#apptokens
func FacebookAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook-access-token",
		Regex:       generateUniqueTokenRegex(`\d{15,16}\|[0-9a-z\-_]{27}`, true),
	}

	// validate
	tps := []string{
		`{"access_token":"911602140448729|AY-lRJZq9BoDLobvAiP25L7RcMg","token_type":"bearer"}`, // gitleaks:allow
		`1308742762612587|rhoK1cbv0DOU_RTX_87O4MkX7AI`,                                         // gitleaks:allow
		`1477036645700765|wRPf2v3mt2JfMqCLK8n7oltrEmc`,                                         // gitleaks:allow
	}
	return validate(r, tps, nil)
}

// https://developers.facebook.com/docs/facebook-login/guides/access-tokens/#pagetokens
func FacebookPageAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook-page-access-token",
		Regex:       generateUniqueTokenRegex("EAA[MC]"+alphaNumeric("20,"), true),
		Keywords:    []string{"EAAM", "EAAC"},
	}

	// validate
	tps := []string{
		`EAAM9GOnCB9kBO2frzOAWGN2zMnZClQshlWydZCrBNdodesbwimx1mfVJgqZBP5RSpMfUzWhtjTTXHG5I1UlvlwRZCgjm3ZBVGeTYiqAAoxyED6HaUdhpGVNoPUwAuAWWFsi9OvyYBQt22DGLqMIgD7VktuCTTZCWKasz81Q822FPhMTB9VFFyClNzQ0NLZClt9zxpsMMrUZCo1VU1rL3CKavir5QTfBjfCEzHNlWAUDUV2YZD`, // gitleaks:allow
		`EAAM9GOnCB9kBO2zXpAtRBmCrsPPjdA3KeBl4tqsEpcYd09cpjm9MZCBIklZBjIQBKGIJgFwm8IE17G5pipsfRBRBEHMWxvJsL7iHLUouiprxKRQfAagw8BEEDucceqxTiDhVW2IZAQNNbf0d1JhcapAGntx5S1Csm4j0GgZB3DuUfI2HJ9aViTtdfH2vjBy0wtpXm2iamevohGfoF4NgyRHusDLjqy91uYMkfrkc`,          // gitleaks:allow
		`- name: FACEBOOK_TOKEN
		value: "EAACEdEose0cBA1bad3afsf2aew"`, // gitleaks:allow
	}
	return validate(r, tps, nil)
}
