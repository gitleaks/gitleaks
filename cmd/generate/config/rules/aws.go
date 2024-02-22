package rules

import (
	"regexp"
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

var credFileAccessKey = "aws_access_key_id=ASIA" + strings.ToUpper(secrets.NewSecret(hex("16")))
var credFileSecretKey = "aws_secret_access_key=" + secrets.NewSecret(hex("40"))
var credFileSessionToken = "aws_session_token=" + secrets.NewSecret(hex("928"))

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		RuleID:      "aws-access-token",
		Regex: regexp.MustCompile(
			"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
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
		`"RoleId": "AROAWORVRXQ5NC76T7223"`,
		credFileSecretKey,
		credFileSessionToken,
	}
	return validate(r, tps, fps)
}
