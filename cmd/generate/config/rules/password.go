package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Password() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "password",
		Description: "Detected a password in a configuration file or code, which may lead to unauthorized access.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"passw(?:or)?d",
			"passwd",
			"pwd",
		}, alphaNumericExtendedLong("6,64"), true),
		Keywords: []string{
			"passwd",
			"password",
			"pwd",
		},
		Allowlists: []*config.Allowlist{
			{
				// Exclude strings that are only alphabetic (no digits or special chars)
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`^[a-zA-Z]+$`),
				},
			},
			{
				Description:    "Allowlist for common password false positives",
				MatchCondition: config.AllowlistMatchOr,
				RegexTarget:    "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)(?:` +
						// password related field names, not values
						`passw(?:or)?d[_.-]?(?:file|hash|length|policy|reset|confirm|confirmation|salt|strength|expire|expiry|change|update|min|max|url|uri|path|field|input|box|form|name|key|id|ref|var|env)` +
						`|(?:forgot|change|update|reset|confirm|new|old|current|default|temp|temporary|initial)[_.-]?passw(?:or)?d` +
						`|(?:hash|encode|decode|encrypt|decrypt|verify|validate|check|match|compare|set|get|has)[_.-]?passw(?:or)?d` +
						`|no[_.-]?passw(?:or)?d` +
						`)`),
				},
				StopWords: []string{
					// Common placeholder values
					"changeme",
					"changeit",
					"change_me",
					"change-me",
					"secret",
					"xxxxxx",
					"******",
					"000000",
					"111111",
					"123456",
					"654321",
					"abc123",
					"abcdef",
					"qwerty",
					"asdfgh",
					"zxcvbn",
					// Environment variable patterns
					"${password}",
					"${PASSWORD}",
					"$password",
					"$PASSWORD",
					"$(password)",
					"{{password}}",
					// Placeholder patterns
					"<password>",
					"<PASSWORD>",
					"[password]",
					"[PASSWORD]",
					"{password}",
					"{PASSWORD}",
					"your_password",
					"your-password",
					"yourpassword",
					"my_password",
					"my-password",
					"mypassword",
					"the_password",
					"thepassword",
					// Template/example values
					"example",
					"sample",
					"foobar",
					"redacted",
					"removed",
					"hidden",
					"masked",
					"placeholder",
					// Null/empty equivalents
					"null",
					"none",
					"empty",
					"blank",
					"undefined",
					"notset",
					"not_set",
					"not-set",
					"unset",
					// Test values
					"testpassword",
					"test_password",
					"test-password",
					"testpass",
					"test123",
					"testing",
					"dummypassword",
					"dummy_password",
					"dummypass",
					"fakepassword",
					"fake_password",
					"fakepass",
					"mockpassword",
					"mock_password",
				},
			},
		},
	}

	// validate
	tps := []string{
		// Issue #1999 example
		`{"loginId":"admin","password":"GitHub!23"}`,
		// Various formats
		`password = "MyP@ssw0rd!"`,
		`password: 'S3cr3t!23'`,
		`"password":"Admin@123"`,
		`PASSWORD=Pr0d#567`,
		`pwd: "L0g!n@99"`,
		`passwd="R00t$pass"`,
		// Different assignment styles
		`user_password := "C0mpl3x!"`,
		`db_password => "Db#2024!"`,
	}
	fps := []string{
		// Placeholders
		`password = "changeme"`,
		`password = "your_password"`,
		`password = "<password>"`,
		`password = "${PASSWORD}"`,
		// Field names
		`passwordField = "user_input"`,
		`password_hash = "abc123def"`,
		`forgot_password = true`,
		`reset_password_url = "/reset"`,
		// Alphabetic only (no numbers or special chars)
		`password = "mysecretpassword"`,
		// Too short
		`password = "ab!1"`,
		// Test values
		`password = "testpassword"`,
		`password = "test123"`,
	}
	return utils.Validate(r, tps, fps)
}

func alphaNumericExtendedLong(length string) string {
	// Extended character class including common password special characters
	// Excludes quote characters (", ', `) as they are handled by regex structure
	return `[a-zA-Z0-9!@#$%^&*()\-_+=\[\]{}|\\;:,.<>/?~]{` + length + `}`
}
