package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"regexp"
)

func GenericCredential() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "generic-api-key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"key",
			"api",
			"token",
			"secret",
			"credential",
			"creds",
			"passwd",
			"password",
			"auth",
			"access",
		}, `[0-9a-z\-_.=]{10,150}`, true),
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"credential",
			"creds",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy: 3.5,
		Allowlists: []config.Allowlist{
			{
				Description:    "Allowlist for Generic API Keys",
				MatchCondition: config.AllowlistMatchOr,
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(` +
						`public[_.-]?(key|token)` + // public key -> not a secret
						`|api[_.-]?(version|id)` + // version/id -> not a secret
						`|(secret)[_.-]?name` + // name of e.g. env variable
						`|issuerkeyhash` + // part of ssl cert
						`|(?-i:[DdMm]onkey|[DM]ONKEY)|keying` + // common words containing "key"
						`|(primary|foreign|natural|definition|hot)[_.-]?key` +
						`|key[_.-]?(alias|board|code|stone|storetype|word|up|down|left|right)` +
						`|rapid|capital` + // common words containing "api"
						`)`),
				},
				RegexTarget: "match",
				StopWords:   DefaultStopWords,
			},
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"), //gitleaks:allow
		utils.GenerateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
		`"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`passwd = ` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`private-key: ` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{100}`),
		`mySecretString=` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		`some_api_token_123 = "` + newPlausibleSecret(`[a-zA-Z0-9]{60}`) + `"`,
		`todo_secret_do_not_commit = ` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		`creds = ` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),
	}
	fps := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

R5: Regulatory--21`,
		`public_key = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`clientId = "73082700-1f09-405b-80d0-3131bfd6272d"`,
		`MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1`,
		`COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT`,
		`LLM_SECRET_NAME = "NEXUS-GPT4-API-KEY"`,
		`keyword: "Befaehigung_P2"`,
		`minisat-master-keying:x64-uwp=fail`,
		`monkeys-audio:mx64-uwp=fail`,
		`rapidstring:marm64-uwp=fail`,
		`<entry key="jetbrains.mps.v8_elimination" value="executed" />`,
		`event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'`,
		`primaryKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`foreignKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`key_down_event=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`issuerKeyHash=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
	}
	return utils.Validate(r, tps, fps)
}

func newPlausibleSecret(regex string) string {
	allowList := config.Allowlist{StopWords: DefaultStopWords}
	// attempt to generate a random secret,
	// retrying until it contains at least one digit and no stop words
	// TODO: currently the DefaultStopWords list contains many short words,
	//  so there is a significant chance of generating a secret that contains a stop word
	for {
		secret := secrets.NewSecret(regex)
		if !regexp.MustCompile(`[1-9]`).MatchString(secret) {
			continue
		}
		if allowList.ContainsStopWord(secret) {
			continue
		}
		return secret
	}
}
