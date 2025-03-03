package rules

import (
	"encoding/base64"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func SentryAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sentry-access-token",
		Description: "Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sentry"}, utils.Hex("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sentry",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sentry", secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}

func SentryOrgToken() *config.Rule {

	// format: sntrys_[base64_json]_[base64_secret]
	// the json contains the following fields : {"iat": ,"url": ,"region_url": ,"org": }
	// Specification: https://github.com/getsentry/rfcs/blob/main/text/0091-ci-upload-tokens.md
	// Some test cases from official parser:
	// https://github.com/getsentry/sentry-cli/blob/693d62167041846e2da823b7f3b0f21b673b5b1f/src/utils/auth_token/test.rs
	// To detect the token, this rule checks for the following base64-encoded json fragments :
	// eyJpYXQiO = `{"iat":`,
	// LCJyZWdpb25fdXJs = `,"region_url`
	// InJlZ2lvbl91cmwi = `"region_url"`
	// cmVnaW9uX3VybCI6 = `region_url":`

	// define rule
	r := config.Rule{
		RuleID:      "sentry-org-token",
		Description: "Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data.",
		Regex:       regexp.MustCompile(`\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)`),
		Entropy:     4.5,
		Keywords:    []string{"sntrys_eyJpYXQiO"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sentry",
		`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`, // gitleaks:allow
	)
	tps = append(tps, utils.GenerateSampleSecrets("sentry",
		`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`, // gitleaks:allow
	)...)
	tps = append(tps,
		` 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`, // gitleaks:allow
	)

	encodedJson := base64.StdEncoding.EncodeToString([]byte(secrets.NewSecret(
		`\{"iat":[\d\.]{3,6},"url":"https://\w{10,20}","region_url":"https://\w{20,30}","org":"\w{5,10}"\}`)))
	generatedToken := `sntrys_` + encodedJson + `_` + secrets.NewSecret(`[a-zA-Z0-9+/]{43}`)
	tps = append(tps,
		generatedToken,
		"<token>"+generatedToken+"</token>",
		"https://example.com?token="+generatedToken+"&other=stuff",
	)

	fps := []string{
		secrets.NewSecret(`sntrys_[a-zA-Z0-9]{90}_[a-zA-Z0-9]{43}`),          // does not contain encoded json
		`sntrys_` + encodedJson + `_` + secrets.NewSecret(`[a-zA-Z0-9]{42}`), // too short
		`sntrys_` + encodedJson + `_` + secrets.NewSecret(`[a-zA-Z0-9]{44}`), // too long
	}

	return utils.Validate(r, tps, fps)
}

func SentryUserToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sentry-user-token",
		Description: "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
		Regex:       utils.GenerateUniqueTokenRegex(`sntryu_[a-f0-9]{64}`, false),
		Entropy:     3.5,
		Keywords:    []string{"sntryu_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sentry", secrets.NewSecret(`sntryu_[a-f0-9]{64}`))
	fps := []string{
		secrets.NewSecret(`sntryu_[a-f0-9]{63}`), // too short
		secrets.NewSecret(`sntryu_[a-f0-9]{65}`), // too long
		secrets.NewSecret(`sntryu_[a]{64}`),      // low entropy
	}
	return utils.Validate(r, tps, fps)
}
