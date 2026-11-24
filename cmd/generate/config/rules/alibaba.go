package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// alibabaAccessPair is an Alibaba Cloud credential pair as downloaded from
// the Alibaba console in CSV format. See:
// https://github.com/gitleaks/gitleaks/issues/1348
var alibabaAccessPair = "AccessKey ID,AccessKey Secret\nLTAI" + secrets.NewSecret(utils.Hex("20")) + "," + secrets.NewSecret(utils.AlphaNumeric("30"))

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		// Like utils.GenerateUniqueTokenRegex, but also allows a trailing
		// comma so the key is detected in CSV exports from the Alibaba
		// console, where the AccessKey ID is followed by a comma.
		Regex:    regexp.MustCompile(`\b(LTAI(?i)[a-z0-9]{20})(?:[\x60'"\s;,]|\\[nr]|$)`),
		Entropy:  2,
		Keywords: []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecret(utils.Hex("20")) + "\"",
		alibabaAccessPair,
	}
	return utils.Validate(r, tps, nil)
}

func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		// The secret is either assigned to an `alibaba`/`accesskey`
		// identifier, or it follows its AccessKey ID in a CSV export from
		// the Alibaba console (`LTAI<id>,<secret>`).
		Regex: utils.MergeRegexps(
			utils.GenerateSemiGenericRegex([]string{"alibaba", "accesskey"}, utils.AlphaNumeric("30"), true),
			regexp.MustCompile(`\bLTAI(?i)[a-z0-9]{20},[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;,]|\\[nr]|$)`),
		),
		Entropy:  2,
		Keywords: []string{"alibaba", "accesskey", "ltai"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("alibaba", secrets.NewSecret(utils.AlphaNumeric("30")))
	tps = append(tps, utils.GenerateSampleSecrets("accesskey", secrets.NewSecret(utils.AlphaNumeric("30")))...)
	tps = append(tps, alibabaAccessPair)
	fps := []string{
		`accesskey = "AKIAIOSFODNN7EXAMPLE"`, // AWS access key id (20 chars)
	}
	return utils.Validate(r, tps, fps)
}
