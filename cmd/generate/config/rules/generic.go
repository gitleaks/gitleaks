package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func GenericCredential() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "generic-api-key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex: generateSemiGenericRegex([]string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		}, `\S{10,150}`, true),
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy: 3.5,
		Allowlist: config.Allowlist{
			StopWords: DefaultStopWords,
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"),
		generateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
		`"client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`"password: 'edf8f16608465858a6c9e3cccb97d3c2'"`,
		"<password>edf8f16608465858a6c9e3cccb97d3c2</password>",
		`<element password="edf8f16608465858a6c9e3cccb97d3c2" />`,
		"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
		`{ "access-key": "6da89121079f83b2eb6acccf8219ea982c3d79bccc", }`,
		`"{ \"access-key\": \"6da89121079f83b2eb6acccf8219ea982c3d79bccc\", }"`,
		`access_key           = "kgfur834kmjfdoi34i9"`,
		`TokenKey: b@d0@u7H50K3nx`,
		`token_key: "gF[wSKyJmBhAFASD%3D"`,
		`token = "weq32C232g37g2h3gdh3K2hT72hXuL2h3ghS34hD"`,
		`client_secret = "F-oS9Su%}<>[];#"`,
	}
	fps := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

		R5: Regulatory--21`,

		`"client_id" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
		`"client_secret" : "4v7b9n2k5h",`, // entropy: 3.32
		`"password: 'comp123!'"`,
		"<password>MyComp9876</password>", // entropy: 3.32
		`<element password="Comp4567@@" />`,
		"M_DB_PASSWORD= aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"GITHUB_TOKEN: ${GITHUB_TOKEN}",
		"password = 'your_password_here'",
		"https://google.com?user=abc&password=123",
		`"password": "abcdefg"`,                                   // short password
		`api_key = "C71AAAAE-1D1D-1D1D-1D1D-1D1D1D1D1D1D"`,        // low entropy
		`secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, // end with "Example Key" stop words
	}
	return validate(r, tps, fps)
}
