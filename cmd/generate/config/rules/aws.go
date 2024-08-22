package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/

var credFileAccessKey = "aws_access_key_id=AKIALALEMEL33243OLIB" // gitleaks:allow
var credFileSecretKey = "aws_secret_access_key=" + secrets.NewSecret(hex("40"))
var credFileSessionToken = "aws_session_token=" + secrets.NewSecret(hex("928"))

func AWSAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		RuleID:      "aws-access-key",
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

func AWSSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		RuleID:      "aws-secret-key",
		Regex:       generateUniqueTokenRegex("[0-9A-Z+\\/]{40}", true),
		Keywords:    []string{"aws_secret_access_key", "aws_secret", "AwsSecret"},
	}

	// validate
	tps := []string{
		credFileSecretKey,
	}
	fps := []string{
		credFileAccessKey,
		credFileSessionToken,
		"  - 4f1d13e1bbebef31175ffe9a8d752609b9edc174",
	}
	return validate(r, tps, fps)
}
