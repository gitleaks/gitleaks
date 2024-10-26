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
			"access",
			"auth",
			`(?-i:[Aa]pi|API)`,
			"credential",
			"creds",
			"key",
			"passwd",
			"password",
			"secret",
			"token",
		}, `[\w.=-]{10,150}`, true),
		Keywords: []string{
			"access",
			"api",
			"auth",
			"key",
			"credential",
			"creds",
			"passwd",
			"password",
			"secret",
			"token",
		},
		Entropy: 3.5,
		Allowlists: []config.Allowlist{
			{
				Description:    "Allowlist for Generic API Keys",
				MatchCondition: config.AllowlistMatchOr,
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(` +
						// Access
						`accessor` +
						// API
						`|api[_.-]?(version|id)` + // version/id -> not a secret
						`|rapid|capital` + // common words containing "api"
						// Auth
						`|author` +
						// Credentials
						`|(?-i:(?:c|jobC)redentials?Id|withCredentials)` + // Jenkins plugins
						// Key
						`|key[_.-]?(alias|board|code|ring|stone|storetype|word|up|down|left|right)` +
						`|issuerkeyhash` + // part of ssl cert
						`|(bucket|primary|foreign|natural|hot)[_.-]?key` +
						`|(?-i:[DdMm]onkey|[DM]ONKEY)|keying` + // common words containing "key"
						// Secret
						`|(secret)[_.-]?name` + // name of e.g. env variable
						// Token

						// General
						`|public[_.-]?(key|token)` + // public key -> not a secret
						`|(key|token)[_.-]?file` +
						`)`),
				},
				RegexTarget: "match",
				StopWords:   DefaultStopWords,
			},
		},
	}

	// validate
	tps := []string{
		// Access
		`'access_token': 'eyJ0eXAioiJKV1slS3oASx=='`,

		// API
		`some_api_token_123 = "` + newPlausibleSecret(`[a-zA-Z0-9]{60}`) + `"`,

		// Auth
		// Credentials
		`"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`creds = ` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),

		// Key
		`private-key: ` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{100}`),

		// Password
		`passwd = ` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),

		// Secret
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`mySecretString=` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		`todo_secret_do_not_commit = ` + newPlausibleSecret(`[a-zA-Z0-9]{30}`),

		// Token
		utils.GenerateSampleSecret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"), //gitleaks:allow
		utils.GenerateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
	}
	fps := []string{
		// Access
		`"accessor":"rA1wk0Y45YCufyfq",`,

		// API
		`this.ultraPictureBox1.Name = "ultraPictureBox1";`,
		`rapidstring:marm64-uwp=fail`,
		`event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'`,
		`COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT`,
		`MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1`,

		// Auth
		`author = "james.fake@ymail.com",`,

		// Credentials
		`withCredentials([usernamePassword(credentialsId: '29f63271-dc2f-4734-8221-5b31b5169bac', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {`,
		`credentialsId: 'ff083f76-7804-4ef1-80e4-fe975bb9141b'`,
		`jobCredentialsId: 'f4aeb6bc-2a25-458a-8111-9be9e502c0e7'`,
		`  "credentialId": "B9mTcFSck2LzJO2S3ols63",`,

		// Key
		`keyword: "Befaehigung_P2"`,
		`public_key = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`monkeys-audio:mx64-uwp=fail`,
		`primaryKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`foreignKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`key_down_event=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`issuerKeyHash=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`<entry key="jetbrains.mps.v8_elimination" value="executed" />`,
		`minisat-master-keying:x64-uwp=fail`,
		`IceSSL.KeyFile=s_rsa1024_priv.pem`,
		`"bucket_key": "SalesResults-1.2"`,
		//`<TAR key="REF_ID_923.properties" value="/opts/config/alias/"/>`,
		`<key tag="SecurityIdentifier" name="SecurityIdentifier" type="STRING" />`,
		//`packageKey":` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),

		// Password
		`password combination.

R5: Regulatory--21`,
		`PuttyPassword=0`,

		// Secret
		`LLM_SECRET_NAME = "NEXUS-GPT4-API-KEY"`,

		// Token
		`publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`<SourceFile SourceLocation="F:\Extracts\" TokenFile="RTL_INST_CODE.cer">`,

		// General
		`clientId = "73082700-1f09-405b-80d0-3131bfd6272d"`,
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
