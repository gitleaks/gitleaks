package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// Database connection strings carry the password inline, and every Supabase,
// Heroku, Railway and Render application ships one as DATABASE_URL. The default
// config has no rule for them: the only `user:pass@` rule is sidekiq-sensitive-url,
// hardcoded to contribsys.com, and `mysql`/`mongodb` appear only as stopwords
// inside generic-api-key — a rule the docs themselves suggest disabling.
func DatabaseConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "database-connection-string",
		Description: "Identified a database connection string containing an inline password, which could grant direct access to application data.",
		Regex:       regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?)://[^\s:@/\\]{1,64}:([^\s:@/\\]{3,128})@[^\s/\\?#'"]{1,256}`),
		SecretGroup: 1,
		Entropy:     2,
		Keywords:    []string{"postgres", "mysql", "mariadb", "mongodb"},
		Allowlists: []*config.Allowlist{
			{
				Description: "local and container-internal hosts",
				RegexTarget: "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1]?|host\.docker\.internal|db|database|postgres(?:ql)?|mysql|mariadb|mongo(?:db)?)(?::\d+)?(?:[/?#]|$)`),
				},
			},
			{
				Description: "placeholder and templated passwords",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)^(?:pass(?:word)?|passwd|pwd|secret|change(?:it|me|_me)|example|sample|test|root|admin|user|your[_-]?password|my[_-]?password|x{3,}|\*{3,}|\.{3,})$`),
					regexp.MustCompile(`^\$(?:\w+|\{[^}]+})$`),       // $PASSWORD or ${PASSWORD}
					regexp.MustCompile(`^\$?\{\{[^}]+}}$`),           // ${{ secrets.X }} or {{ .Values.x }}
					regexp.MustCompile(`^<[^>]+>$`),                  // <password>
					regexp.MustCompile(`^\[[^]]+]$`),                 // [password]
					regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_]*%$`), // %PASSWORD%
				},
			},
		},
	}

	tps := []string{
		`DATABASE_URL=postgres://app_user:hunter2xK9@db.example.com:5432/app`,
		`postgresql://svc:7fQ2vLp0Rz@prod-db.internal.example.net/records?sslmode=require`,
		`mysql://root:s3cr3tP4ss@mysql-prod.example.com:3306/wordpress`,
		`mongodb://admin:Zx91QvbT2m@cluster0.example.com:27017/admin`,
		`mongodb+srv://reader:Kq7Wb2nT4x@cluster0.abcde.mongodb.net/test`,
	}
	fps := []string{
		// Local development and docker-compose — deliberately not flagged.
		`postgres://user:pass@localhost:5432/test`,
		`postgres://postgres:postgres@db:5432/postgres`,
		`mongodb://root:example@mongo:27017/`,
		// Placeholders and templated values.
		`postgres://user:<password>@db.example.com:5432/app`,
		`postgres://user:${DB_PASSWORD}@db.example.com:5432/app`,
		// No credentials at all.
		`postgres://db.example.com:5432/app`,
		`postgresql://app_user@db.example.com:5432/app`,
	}
	return utils.Validate(r, tps, fps)
}
