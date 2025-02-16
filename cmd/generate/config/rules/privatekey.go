package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func PrivateKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "private-key",
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`),
		Keywords:    []string{"-----BEGIN"},
	}

	// validate
	tps := []string{`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3
yxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
	} // gitleaks:allow
	fps := []string{
		`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----`,
	}
	return utils.Validate(r, tps, fps)
}

func PrivateKeyPKCS12File() *config.Rule {
	// https://en.wikipedia.org/wiki/PKCS_12
	r := config.Rule{
		RuleID:      "pkcs12-file",
		Description: "Found a PKCS #12 file, which commonly contain bundled private keys.",
		Path:        regexp.MustCompile(`(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`),
	}

	// validate
	tps := map[string]string{
		"security/es_certificates/opensearch/es_kibana_client.p12": "",
		"cagw_key.P12": "",
		"ToDo/ToDo.UWP/ToDo.UWP_TemporaryKey.pfx": "",
	}
	fps := map[string]string{
		"doc/typenum/type.P126.html":         "",
		"scripts/keeneland/syntest.p1200.sh": "",
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
