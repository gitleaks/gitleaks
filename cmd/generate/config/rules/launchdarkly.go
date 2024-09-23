package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LaunchDarklyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "launchdarkly-access-token",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		Regex:       utils.GenerateUniqueTokenRegex("(?:api|sdk)-"+utils.Hex8_4_4_4_12(), false),
		Entropy:     3,
		Keywords: []string{
			"api-", "sdk-",
		},
		// https://apidocs.launchdarkly.com/tag/Other#operation/getCallerIdentity
		Verify: &config.Verify{
			HTTPVerb: "GET",
			URL:      "https://app.launchdarkly.com/api/v2/caller-identity",
			Headers: map[string]string{
				"Authorization": "${launchdarkly-access-token}",
			},
			ExpectedStatus: []int{200},
			ExpectedBodyContains: []string{
				`"accountId":`,
			},
		},
	}

	// validate
	tps := []string{
		// API
		utils.GenerateSampleSecret("token", secrets.NewSecret("api-"+utils.Hex8_4_4_4_12())),
		` # This can also be set via the LAUNCHDARKLY_ACCESS_TOKEN environment variable.
  # access_token = "api-dd8ce121-cd11-401c-be02-322b7362111d"`, // https://github.com/turbot/steampipe-plugin-launchdarkly/blob/c642c23073cf404213018de045a7c81e1f9133d5/docs/index.md?plain=1#L80
		// SDK
		utils.GenerateSampleSecret("ld_token", secrets.NewSecret("sdk-"+utils.Hex8_4_4_4_12())),
		`# Set sdk_key to your LaunchDarkly SDK key before running
sdk_key = "sdk-90f53fa4-627f-4b7b-b485-06cdd4fc3993"`, // https://github.com/mcnayak/hello-python/blob/a5035db3c29dbc7901c4b6b5c4746d2d662dac61/app.py#L16
	}
	fps := []string{
		// api
		`    ldClient, err = ld.MakeCustomClient("sdk-12345678-9999-9999-9999-999999999999", config, 10*time.Second)`,
		`api_key: RGAPI-52eb9c9f-470e-4965-8c21-9f668c07e431`,
		// sdk
		`const ldclient = LaunchDarkly.init('sdk-00000000-aaaa-bbbb-cccc-dddddddddddd');`,
	}
	return utils.Validate(r, tps, fps)
}
