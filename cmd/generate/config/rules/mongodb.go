package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func MongoDBAtlasPrivateKey() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-atlas-private-key",
		Description: "Detected a MongoDB Atlas API private key, which could allow unauthorized Atlas administration API access when paired with a public key.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			`(?:mongodb(?:[_ .-]?atlas)?|atlas)(?:[_ .-]?api)?(?:[_ .-]?(?:private|secret))[_ .-]?key`,
		}, utils.Hex8_4_4_4_12(), true),
		Keywords: []string{
			"atlas_private",
			"atlas-private",
			"atlasprivate",
			"mongodb_atlas",
			"mongodb-atlas",
			"mongodbatlas",
		},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`^0{8}-0{4}-0{4}-0{4}-0{12}$`),
				},
			},
		},
	}

	tps := []string{
		`ATLAS_PRIVATE_KEY="4b18315e-6b7d-4337-b449-5d38f5a189ec"`,
		`mongodb_atlas_api_private_key = "d0f7c488-5d6b-4fea-9fae-e6b7bcf5e3c1"`,
		`const atlasPrivateKey = "f17a2c01-89ef-49c9-a5a8-c735a1c0c3f6"`,
	}
	fps := []string{
		`atlas_project_id = "5a0a1e7e0f2912c554080adc"`,
		`atlasPrivateLinkEndpointId = "4b18315e-6b7d-4337-b449-5d38f5a189ec"`,
		`mongodb_atlas_api_private_key = "00000000-0000-0000-0000-000000000000"`,
	}

	return utils.Validate(r, tps, fps)
}

func MongoDBAtlasPublicKey() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-atlas-public-key",
		Description: "Detected a MongoDB Atlas API public key, which can identify Atlas administration credentials and increases risk when exposed with a private key.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			`(?:mongodb(?:[_ .-]?atlas)?|atlas)(?:[_ .-]?api)?(?:[_ .-]?public)[_ .-]?key`,
		}, `[a-z0-9]{10}`, true),
		Keywords: []string{
			"atlas_public",
			"atlas-public",
			"atlaspublic",
			"mongodb_atlas",
			"mongodb-atlas",
			"mongodbatlas",
		},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)^(?:publickey|yourpublic|examplekey|samplekey)$`),
					regexp.MustCompile(`(?i)^[a-z]{10}$`),
					regexp.MustCompile(`^[0-9]{10}$`),
				},
			},
		},
	}

	tps := []string{
		`ATLAS_PUBLIC_KEY="qj4Zrh8e6A"`,
		`mongodb_atlas_api_public_key = "Ab3dE6fGh9"`,
		`const atlas_public_key = "zX7cV4bN2m"`,
	}
	fps := []string{
		`atlas_public_key = "abcdefghij"`,
		`atlas_public_key = "0123456789"`,
		`atlas_public_key = "PUBLICKEY"`,
		`atlas_project_name = "mongodb123"`,
	}

	return utils.Validate(r, tps, fps)
}

func MongoDBAtlasServiceAccountToken() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-atlas-service-account-token",
		Description: "Detected a MongoDB Atlas service account client secret, which could allow unauthorized Atlas administration API access when paired with a service account client ID.",
		Regex:       utils.GenerateUniqueTokenRegex(`mdb_sa_sk_[A-Za-z0-9_-]{40}`, false),
		Entropy:     3,
		Keywords:    []string{"mdb_sa_sk_"},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)^mdb_sa_sk_x{40}$`),
					regexp.MustCompile(`^mdb_sa_sk_[0-9]{40}$`),
				},
			},
		},
	}

	tps := utils.GenerateSampleSecrets("mongodbAtlasServiceAccount", "mdb_sa_sk_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	tps = append(tps,
		`export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("18"))+`_-`+secrets.NewSecret(utils.AlphaNumeric("20"))+`"`,
		`MDB_ATLAS_SERVICE_ACCOUNT_SECRET='mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("12"))+`-`+secrets.NewSecret(utils.AlphaNumeric("27"))+`'`,
		`clientSecret: "mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("15"))+`_`+secrets.NewSecret(utils.AlphaNumeric("24"))+`"`,
	)
	fps := []string{
		`atlas api serviceAccounts getServiceAccount --clientId mdb_sa_id_1234567890abcdef12345678 --orgId 4888442a3354817a7320eb61`,
		`export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_` + strings.Repeat("x", 40) + `"`,
	}

	return utils.Validate(r, tps, fps)
}

func MongoDBConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-connection-string",
		Description: "Detected a MongoDB connection string with embedded credentials, potentially exposing direct database access and sensitive application data.",
		Regex:       regexp.MustCompile(`(?i)\b(mongodb(?:\+srv)?:\/\/(?:[^:@\/\s'"\x60]{1,100}):(?:[^@\/\s'"\x60]{3,100})@(?:\[[0-9a-f:]+\]|[-a-z0-9.]+)(?::\d{2,5})?(?:,(?:\[[0-9a-f:]+\]|[-a-z0-9.]+)(?::\d{2,5})?)*(?:\/[^\s'"\x60)]*)?)(?:[\x60'"\s;]|\\[nr]|$)`),
		Keywords:    []string{"mongodb://", "mongodb+srv://"},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?:\/\/(?:user(?:name)?|foo):(?:pass(?:word)?|bar)(?:[^@\/]*)?@`),
					regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?:\/\/[^\s'"\x60]*(?:\$\{\{[^}]+}}|\$\{[^}]+}|\$[A-Za-z_][A-Za-z0-9_]*|{{[^}]+}}|<[^>]+>|\[[^]]+])[^\s'"\x60]*`),
				},
			},
		},
	}

	tps := []string{
		`MONGODB_URI="mongodb+srv://app-user:q9V7nB2K4xL8@cluster0.mongodb.net/sample_mflix?retryWrites=true&w=majority"`,
		`spring.data.mongodb.uri=mongodb://svc-reader:Az9xV2pLm6Q@mongo1.internal.example:27017,mongo2.internal.example:27017/app?replicaSet=rs0&authSource=admin`,
		`mongo_url: 'mongodb://backup-user:p%40ssw0rd123@db.example.com:27017/admin'`,
		`export MONGO_URL=mongodb://reader-user:Qv8h2Lp4Rk7m@db-shard-00.example.net:27017/app?authSource=admin`,
	}
	fps := []string{
		`MONGODB_URI="mongodb://user:pass@localhost:27017/app"`,
		`spring.data.mongodb.uri=mongodb+srv://<username>:<password>@cluster.mongodb.net/app`,
		`mongodb://$MONGODB_USER:$MONGODB_PASSWORD@cluster.mongodb.net/app`,
		`mongodb+srv://${DB_USER}:${DB_PASS}@cluster.mongodb.net/`,
		`mongodb://{{ .Values.mongoUser }}:{{ .Values.mongoPassword }}@mongo.example.net/app`,
	}

	return utils.Validate(r, tps, fps)
}
