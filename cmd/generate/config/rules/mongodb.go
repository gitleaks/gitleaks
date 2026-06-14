package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func MongoDBConnectionString() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mongodb-connection-string",
		Description: "Detected a MongoDB connection string with embedded credentials, risking unauthorized database access.",
		Regex:       regexp.MustCompile(`mongodb(?:\+srv)?://[^:\s"']+:[^@\s"']+@[^\s"']+`),
		Keywords:    []string{"mongodb://", "mongodb+srv://"},
	}

	// validate
	tps := []string{
		`mongodb://testuser:testpass@localhost:27017/mytestdb`,
		`mongodb+srv://admin:secretpass@cluster.mongodb.net/prod`,
		`MONGO_URI=mongodb://user:password123@db.example.com:27017/database`,
		`"mongodb://root:root@mongo:27017/admin?authSource=admin"`,
	}
	fps := []string{
		`mongodb://localhost:27017/mydb`,         // no credentials
		`mongodb+srv://cluster.mongodb.net/mydb`, // no credentials
	}
	return utils.Validate(r, tps, fps)
}
