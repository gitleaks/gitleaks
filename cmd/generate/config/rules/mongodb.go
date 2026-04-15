package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

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
