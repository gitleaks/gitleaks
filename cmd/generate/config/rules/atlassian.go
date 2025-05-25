package rules

import (
	"crypto/md5"
	"encoding/hex"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Atlassian() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.",
		RuleID:      "atlassian-api-token",
		Regex: utils.MergeRegexps(
			utils.GenerateSemiGenericRegex(
				[]string{"atlassian", "confluence", "jira"},
				`[a-zA-Z0-9]{24}`,
				false,
			),
			utils.GenerateUniqueTokenRegex(`ATATT3[A-Za-z0-9_\-=]{186}`, false),
		),
		Entropy:  3.5,
		Keywords: []string{"atlassian", "confluence", "jira", "atatt3"},
		Allowlists: []*config.Allowlist{
			{
				Description: "Validate token checksum",
				Expression:  `(secret.size() == 24 && secret.substring(20, 24) != md5(secret.substring(0, 20)).substring(0,4)) || (secret.size() == 192 && secret.substring(184) != crc32(secret.substring(0, 184)).upperAscii())`,
			},
		},
	}

	// validate
	v1Secret := func() string {
		s := secrets.NewSecret(utils.AlphaNumeric("20"))
		return s + md5hash(s)[:4]
	}()
	tps := utils.GenerateSampleSecrets("atlassian", v1Secret)
	tps = append(tps, utils.GenerateSampleSecrets("confluence", v1Secret)...)
	tps = append(tps, utils.GenerateSampleSecrets("jira", v1Secret)...)
	tps = append(tps, utils.GenerateSampleSecrets("jira", "ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6")...)

	fps := []string{
		`"atlassian_TOKEN := \"7veqnbx558kv7ixm9rzb2yli\"`,
		`$atlassianToken .= "sm7p90vzq0dxozabk9pj6905"`,
		`token => "ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E5"`,
	}
	return utils.Validate(r, tps, fps)
}

func md5hash(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
