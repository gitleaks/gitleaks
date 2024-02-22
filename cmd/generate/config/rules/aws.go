package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

var credFileAccessKey = "aws_access_key_id=AKIALALEMEL33243OLIB" // gitleaks:allow
var credFileSecretKey = "aws_secret_access_key=" + secrets.NewSecret(hex("40"))
var credFileSessionToken = "aws_session_token=" + secrets.NewSecret(hex("928"))

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		RuleID:      "aws-access-token",
		Regex:       generateUniqueTokenRegex("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}", false),
		Keywords: []string{
			"AKIA",
			"ASIA",
			"ABIA",
			"ACCA",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("AWS", "AKIALALEMEL33243OLIB"), // gitleaks:allow
		credFileAccessKey,
	}
	fps := []string{
		generateSampleSecret("AWS", "AKIALALEMEL33243O000"), // includes 0 which can't be result of base32 encoding
		`"RoleId": "AROAWORVRXQ5NC76T7223"`,
		credFileSecretKey,
		credFileSessionToken,
	}
	return validate(r, tps, fps)
}
