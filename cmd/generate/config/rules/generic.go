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
				RegexTarget:    "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(` +
						// Access
						`accessor` +
						`|access[_.-]?id` +
						// API
						`|api[_.-]?(version|id)` + // version/id -> not a secret
						`|rapid|capital` + // common words containing "api"
						`|[a-z0-9-]*?api[a-z0-9-]*?:jar:` + // Maven META-INF dependencies that contain "api" in the name.
						// Auth
						`|author` +
						`|X-MS-Exchange-Organization-Auth` + // email header
						`|Authentication-Results` + // email header
						// Credentials
						`|(credentials?[_.-]?id|withCredentials)` + // Jenkins plugins
						// Key
						`|(bucket|foreign|hot|natural|primary|schema|sequence)[_.-]?key` +
						`|key[_.-]?(alias|board|code|ring|selector|size|stone|storetype|word|up|down|left|right)` +
						`|key(store|tab)[_.-]?(file|path)` +
						`|issuerkeyhash` + // part of ssl cert
						`|(?-i:[DdMm]onkey|[DM]ONKEY)|keying` + // common words containing "key"
						// Secret
						`|(secret)[_.-]?name` + // name of e.g. env variable
						`|UserSecretsId` + // https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-8.0&tabs=linux

						// Token

						// General
						`|(api|credentials|token)[_.-]?(endpoint|ur[il])` +
						`|public[_.-]?(key|token)` + // public key -> not a secret
						`|(key|token)[_.-]?file` +
						`)`),
				},
				StopWords: DefaultStopWords,
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443") //gitleaks:allow
	tps = append(tps, utils.GenerateSampleSecrets("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB")...)
	tps = append(tps,
		// Access
		`'access_token': 'eyJ0eXAioiJKV1slS3oASx=='`,

		// API
		`some_api_token_123 = "`+newPlausibleSecret(`[a-zA-Z0-9]{60}`)+`"`,

		// Auth
		// Credentials
		`"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`creds = `+newPlausibleSecret(`[a-zA-Z0-9]{30}`),

		// Key
		`private-key: `+newPlausibleSecret(`[a-zA-Z0-9\-_.=]{100}`),

		// Password
		`passwd = `+newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		// TODO: `ID=dbuser;password=` + newPlausibleSecret(`[a-zA-Z0-9+/]{30}={0,3}`) + `;"`,

		// Secret
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`mySecretString=`+newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		`todo_secret_do_not_commit = `+newPlausibleSecret(`[a-zA-Z0-9]{30}`),

		// Token
		utils.GenerateSampleSecret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"), //gitleaks:allow
		utils.GenerateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
	)
	fps := []string{
		// Access
		`"accessor":"rA1wk0Y45YCufyfq",`,
		`report_access_id: e8e4df51-2054-49b0-ab1c-516ac95c691d`,

		// API
		`this.ultraPictureBox1.Name = "ultraPictureBox1";`,
		`rapidstring:marm64-uwp=fail`,
		`event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'`,
		`COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT`,
		`MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1`,
		`[DEBUG]		org.slf4j.slf4j-api:jar:1.7.8.:compile (version managed from default)`,
		`[DEBUG]		org.neo4j.neo4j-graphdb-api:jar:3.5.12:test`,
		`apiUrl=apigee.corpint.com`,
		// TODO: Jetbrains IML files (requires line-level allowlist).
		//`<orderEntry type="library" scope="PROVIDED" name="Maven: org.apache.directory.api:api-asn1-api:1.0.0-M20" level="projcet" />`

		// Auth
		`author = "james.fake@ymail.com",`,
		`X-MS-Exchange-Organization-AuthSource: sm02915.int.contoso.com`,
		`Authentication-Results: 5h.ca.iphmx.com`,

		// Credentials
		`withCredentials([usernamePassword(credentialsId: '29f63271-dc2f-4734-8221-5b31b5169bac', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {`,
		`credentialsId: 'ff083f76-7804-4ef1-80e4-fe975bb9141b'`,
		`jobCredentialsId: 'f4aeb6bc-2a25-458a-8111-9be9e502c0e7'`,
		`  "credentialId": "B9mTcFSck2LzJO2S3ols63",`,
		`environment {
	CREDENTIALS_ID = "K8S_CRED"
}`,
		`dev.credentials.url=dev-lb1.api.f4ke.com:5215`,

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
		`schemaKey = 'DOC_Vector_5_32'`,
		`sequenceKey = "18"`,
		`app.keystore.file=env/cert.p12`,
		`-DKEYTAB_FILE=/tmp/app.keytab`,
		`	doc.Security.KeySize = PdfEncryptionKeySize.Key128Bit;`,
		`o.keySelector=n,o.haKey=!1,`,
		// TODO: Requires line-level allowlists.
		//`<add key="SchemaTable" value="G:\SchemaTable.xml" />`,
		//	`secret:
		//secretName: app-decryption-secret
		//items:
		//	- key: app-k8s.yml
		//	  path: app-k8s.yml`,

		// TODO: https://learn.microsoft.com/en-us/windows/apps/design/style/xaml-theme-resources
		//`<Color x:Key="NormalBrushGradient1">#FFBAE4FF</Color>`,

		// Password
		`password combination.

R5: Regulatory--21`,
		`PuttyPassword=0`,

		// Secret
		`LLM_SECRET_NAME = "NEXUS-GPT4-API-KEY"`,
		`  <UserSecretsId>79a3edd0-2092-40a2-a04d-dcb46d5ca9ed</UserSecretsId>`,

		// Token
		`    access_token_url='https://github.com/login/oauth/access_token',`,
		`publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`<SourceFile SourceLocation="F:\Extracts\" TokenFile="RTL_INST_CODE.cer">`,
		// TODO: `TOKEN_AUDIENCE = "25872395-ed3a-4703-b647-22ec53f3683c"`,

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
