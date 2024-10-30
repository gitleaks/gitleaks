package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

var global_keys = []string{
	`cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`, // gitleaks:allow
	`CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c`,    // gitleaks:allow
	`cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`,                 // gitleaks:allow
}

var api_keys = []string{
	`cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, // gitleaks:allow
	`CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc`,    // gitleaks:allow
	`cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`,          // gitleaks:allow
}

var origin_ca_keys = []string{
	`CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5`,
	`CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed`,
}

var identifiers = []string{"cloudflare"}

func CloudflareGlobalAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cloudflare-global-api-key",
		Description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
		Regex:       utils.GenerateSemiGenericRegex(identifiers, utils.Hex("37"), true),
		Entropy:     2,
		Keywords:    identifiers,
	}

	// validate
	tps := utils.GenerateSampleSecrets("cloudflare", secrets.NewSecret(utils.Hex("37")))
	tps = append(tps, global_keys...)
	fps := append(api_keys, origin_ca_keys...)

	return utils.Validate(r, tps, fps)
}

func CloudflareAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cloudflare-api-key",
		Description: "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.",
		Regex:       utils.GenerateSemiGenericRegex(identifiers, utils.AlphaNumericExtendedShort("40"), true),
		Entropy:     2,
		Keywords:    identifiers,
	}

	// validate
	tps := utils.GenerateSampleSecrets("cloudflare", secrets.NewSecret(utils.AlphaNumericExtendedShort("40")))
	tps = append(tps, api_keys...)
	fps := append(global_keys, origin_ca_keys...)

	return utils.Validate(r, tps, fps)
}

func CloudflareOriginCAKey() *config.Rule {
	ca_identifiers := append(identifiers, "v1.0-")
	// define rule
	r := config.Rule{
		Description: "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "cloudflare-origin-ca-key",
		Regex:       utils.GenerateUniqueTokenRegex(`v1\.0-`+utils.Hex("24")+"-"+utils.Hex("146"), false),
		Entropy:     2,
		Keywords:    ca_identifiers,
	}

	// validate
	tps := utils.GenerateSampleSecrets("cloudflare", "v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5")
	tps = append(tps, origin_ca_keys...)
	fps := append(global_keys, api_keys...)

	return utils.Validate(r, tps, fps)
}
