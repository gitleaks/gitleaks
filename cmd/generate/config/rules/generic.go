package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
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
			"passw(?:or)?d",
			"secret",
			"token",
		}, `[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}`, true),
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
		Allowlists: []*config.Allowlist{
			{
				// NOTE: this is a goofy hack to get around the fact there golang's regex engine does not support positive lookaheads.
				// Ideally we would want to ensure the secret contains both numbers and alphabetical characters, not just alphabetical characters.
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`^[a-zA-Z_.-]+$`),
				},
			},
			{
				Description:    "Allowlist for Generic API Keys",
				MatchCondition: config.AllowlistMatchOr,
				RegexTarget:    "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(?:` +
						// Access
						`access(?:ibility|or)` +
						`|access[_.-]?id` +
						`|random[_.-]?access` +
						// API
						`|api[_.-]?(?:id|name|version)` + // id/name/version -> not a secret
						`|rapid|capital` + // common words containing "api"
						`|[a-z0-9-]*?api[a-z0-9-]*?:jar:` + // Maven META-INF dependencies that contain "api" in the name.
						// Auth
						`|author` +
						`|X-MS-Exchange-Organization-Auth` + // email header
						`|Authentication-Results` + // email header
						// Credentials
						`|(?:credentials?[_.-]?id|withCredentials)` + // Jenkins plugins
						// Key
						`|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key` +
						`|(?:turkey)` +
						`|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)` +
						// Azure KeyVault
						`|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets` +
						`|key(?:store|tab)[_.-]?(?:file|path)` +
						`|issuerkeyhash` + // part of ssl cert
						`|(?-i:[DdMm]onkey|[DM]ONKEY)|keying` + // common words containing "key"
						// Secret
						`|(?:secret)[_.-]?(?:length|name|size)` + // name of e.g. env variable
						`|UserSecretsId` + // https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-8.0&tabs=linux

						// Token
						`|(?:csrf)[_.-]?token` +
						`|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)` + // Maven library coordinates. (e.g., https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt)

						// General
						`|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])` +
						`|public[_.-]?token` +
						`|(?:key|token)[_.-]?file` +
						// Empty variables capturing the next line (e.g., .env files)
						`|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))` +
						`|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z))` +
						`)`),
				},
				StopWords: append(DefaultStopWords,
					"6fe4476ee5a1832882e326b506d14126", // https://github.com/yarnpkg/berry/issues/6201
				),
			},
			{
				RegexTarget: "line",
				Regexes: []*regexp.Regexp{
					// Docker build secrets (https://docs.docker.com/build/building/secrets/#using-build-secrets).
					regexp.MustCompile(`--mount=type=secret,`),
					//  https://github.com/gitleaks/gitleaks/issues/1800
					regexp.MustCompile(`import[ \t]+{[ \t\w,]+}[ \t]+from[ \t]+['"][^'"]+['"]`),
				},
			},
			{
				MatchCondition: config.AllowlistMatchAnd,
				RegexTarget:    "line",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`LICENSE[^=]*=\s*"[^"]+`),
					regexp.MustCompile(`LIC_FILES_CHKSUM[^=]*=\s*"[^"]+`),
					regexp.MustCompile(`SRC[^=]*=\s*"[a-zA-Z0-9]+`),
				},
				Paths: []*regexp.Regexp{
					regexp.MustCompile(`\.bb$`),
					regexp.MustCompile(`\.bbappend$`),
					regexp.MustCompile(`\.bbclass$`),
					regexp.MustCompile(`\.inc$`),
				},
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
		`"user_auth": "am9obmRvZTpkMDY5NGIxYi1jMTcxLTQ4ODYt+TMyYS0wMmUwOWQ1/mIwNjc="`,

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
		` utils.GetEnvOrDefault("api_token", "dafa7817-e246-48f3-91a7-e87653d587b8")`,
		//	`"env": {
		//"API_TOKEN": "Lj2^5O%xi214"`,
	)
	fps := []string{
		// Access
		`"accessor":"rA1wk0Y45YCufyfq",`,
		`report_access_id: e8e4df51-2054-49b0-ab1c-516ac95c691d`,
		`accessibilityYesOptionId = "0736f5ef-7e88-499a-80cc-90c85d2a5180"`,
		`_RandomAccessIterator>
_LIBCPP_CONSTEXPR_AFTER_CXX11 `,

		// API
		`this.ultraPictureBox1.Name = "ultraPictureBox1";`,
		`rapidstring:marm64-uwp=fail`,
		`event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'`,
		`COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT`,
		`MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1`,
		`[DEBUG]		org.slf4j.slf4j-api:jar:1.7.8.:compile (version managed from default)`,
		`[DEBUG]		org.neo4j.neo4j-graphdb-api:jar:3.5.12:test`,
		`apiUrl=apigee.corpint.com`,
		`X-API-Name": "NRG0-Hermes-INTERNAL-API",`,
		// TODO: Jetbrains IML files (requires line-level allowlist).
		// `<orderEntry type="library" scope="PROVIDED" name="Maven: org.apache.directory.api:api-asn1-api:1.0.0-M20" level="projcet" />`

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
		`pub const X509_pubkey_st = struct_X509_pubkey_st;`,
		`|| pIdxKey->default_rc==0`,
		`monkeys-audio:mx64-uwp=fail`,
		`primaryKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`foreignKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`key_down_event=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`issuerKeyHash=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`<entry key="jetbrains.mps.v8_elimination" value="executed" />`,
		`minisat-master-keying:x64-uwp=fail`,
		`IceSSL.KeyFile=s_rsa1024_priv.pem`,
		`"bucket_key": "SalesResults-1.2"`,
		`<key tag="SecurityIdentifier" name="SecurityIdentifier" type="STRING" />`,
		// `packageKey":` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`schemaKey = 'DOC_Vector_5_32'`,
		`sequenceKey = "18"`,
		`app.keystore.file=env/cert.p12`,
		`-DKEYTAB_FILE=/tmp/app.keytab`,
		`	doc.Security.KeySize = PdfEncryptionKeySize.Key128Bit;`,
		`o.keySelector=n,o.haKey=!1,`,
		// TODO: Requires line-level allowlists.
		`                                "key_name": "prod5zyxlmy-cmk",`,
		`                                "kms_key_id": "555ea4a3-d53a-4412-9c66-3a7cb667b0d6",`,
		`	"key_vault_name": "web21prqodx24021",`,
		`  keyVaultToStoreSecrets: cmp2-qat-1208358310`, // e.g., https://github.com/2uasimojo/community-operators-prod/blob/9e51e4c8e0b5caaa3087e8e18e6fb918b2c36643/operators/azure-service-operator/1.0.59040/manifests/azure.microsoft.com_cosmosdbs.yaml#L50
		`,apiKey:"6fe4476ee5a1832882e326b506d14126",`,
		`const validKeyChars = "0123456789abcdefghijklmnopqrstuvwxyz_-."`,
		`const keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"`,
		`key_length = XSalsa20.key_length`,
		`pub const SN_id_Gost28147_89_None_KeyMeshing = "id-Gost28147-89-None-KeyMeshing"`,
		`KeyPair = X25519.KeyPair`,
		`BlindKeySignatures = Ed25519.BlindKeySignatures`,
		`AVEncVideoMaxKeyframeDistance, "2987123a-ba93-4704-b489-ec1e5f25292c"`,
		`            keyPressed = kVK_Return.u16`,
		`timezone_mapping = {
    "Turkey Standard Time": "Europe/Istanbul",
}`, // https://github.com/gitleaks/gitleaks/issues/1799
		// `<add key="SchemaTable" value="G:\SchemaTable.xml" />`,
		//`    { key: '9df21e95-3848-409d-8f94-c675cdfee839', value: 'Americas' },`,
		// `<TAR key="REF_ID_923.properties" value="/opts/config/alias/"/>`,
		//	`secret:
		// secretName: app-decryption-secret
		// items:
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
		`secret_length = X25519.secret_length`,
		`secretSize must be >= XXH3_SECRET_SIZE_MIN`,
		`# get build time secret for authentication
#RUN --mount=type=secret,id=jfrog_secret \
#    JFROG_SECRET = $(cat /run/secrets/jfrog_secret) && \`,

		// Token
		`    access_token_url='https://github.com/login/oauth/access_token',`,
		`publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`<SourceFile SourceLocation="F:\Extracts\" TokenFile="RTL_INST_CODE.cer">`,
		`notes            = "Maven - io.jsonwebtoken:jjwt-jackson-0.11.2"`,
		`csrf-token=Mj2qykJO5rELyHgezQ69nzUX0i3OH67V7+V4eUrLfpuyOuxmiW9rhROG/Whikle15syazJOkrjJa3U2AbhIvUw==`,
		// TODO: `TOKEN_AUDIENCE = "25872395-ed3a-4703-b647-22ec53f3683c"`,

		// General
		`clientId = "73082700-1f09-405b-80d0-3131bfd6272d"`,
		`GITHUB_API_KEY=
DYNATRACE_API_KEY=`,
		`snowflake.password=
jdbc.snowflake.url=`,
		`import { chain_Anvil1_Key, chain_Anvil2_Key } from '../blockchain-tests/pallets/supported-chains/consts';`,

		// Yocto/BitBake
		`SRCREV_moby = "43fc912ef59a83054ea7f6706df4d53a7dea4d80"`,
		`LIC_FILES_CHKSUM = "file://${WORKDIR}/license.html;md5=5c94767cedb5d6987c902ac850ded2c6"`,
	}
	return utils.Validate(r, tps, fps)
}

func newPlausibleSecret(regex string) string {
	allowList := &config.Allowlist{StopWords: DefaultStopWords}
	// attempt to generate a random secret,
	// retrying until it contains at least one digit and no stop words
	// TODO: currently the DefaultStopWords list contains many short words,
	//  so there is a significant chance of generating a secret that contains a stop word
	for {
		secret := secrets.NewSecret(regex)
		if !regexp.MustCompile(`[1-9]`).MatchString(secret) {
			continue
		}
		if ok, _ := allowList.ContainsStopWord(secret); ok {
			continue
		}
		return secret
	}
}
