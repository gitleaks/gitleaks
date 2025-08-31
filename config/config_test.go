package config

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

const configPath = "../testdata/config/"

var regexComparer = func(x, y *regexp.Regexp) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.String() == y.String()
}

type translateCase struct {
	// Configuration file basename to load, from `../testdata/config/`.
	cfgName string
	// Expected result.
	cfg Config
	// Rules to compare.
	rules []string
	// Error to expect.
	wantError error
}

func TestTranslate(t *testing.T) {
	tests := []translateCase{
		// Valid
		{
			cfgName: "generic",
			cfg: Config{
				Title: "gitleaks config",
				Rules: map[string]Rule{"generic-api-key": {
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					Regex:       regexp.MustCompile(`(?i)(?:key|api|token|secret|client|passwd|password|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
					Entropy:     3.5,
					Keywords:    []string{"key", "api", "token", "secret", "client", "passwd", "password", "auth", "access"},
					Tags:        []string{},
				}},
			},
		},
		{
			cfgName: "valid/rule_path_only",
			cfg: Config{
				Rules: map[string]Rule{"python-files-only": {
					RuleID:      "python-files-only",
					Description: "Python Files",
					Path:        regexp.MustCompile(`.py`),
					Keywords:    []string{},
					Tags:        []string{},
				}},
			},
		},
		{
			cfgName: "valid/rule_regex_escaped_character_group",
			cfg: Config{
				Rules: map[string]Rule{"pypi-upload-token": {
					RuleID:      "pypi-upload-token",
					Description: "PyPI upload token",
					Regex:       regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
					Keywords:    []string{},
					Tags:        []string{"key", "pypi"},
				}},
			},
		},
		{
			cfgName: "valid/rule_entropy_group",
			cfg: Config{
				Rules: map[string]Rule{"discord-api-key": {
					RuleID:      "discord-api-key",
					Description: "Discord API key",
					Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
					Entropy:     3.5,
					SecretGroup: 3,
					Keywords:    []string{},
					Tags:        []string{},
				}},
			},
		},

		// Invalid
		{
			cfgName:   "invalid/rule_missing_id",
			cfg:       Config{},
			wantError: errors.New("rule |id| is missing or empty, regex: (?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{64})['\\\"]"),
		},
		{
			cfgName:   "invalid/rule_no_regex_or_path",
			cfg:       Config{},
			wantError: errors.New("discord-api-key: both |regex| and |path| are empty, this rule will have no effect"),
		},
		{
			cfgName:   "invalid/rule_bad_entropy_group",
			cfg:       Config{},
			wantError: errors.New("discord-api-key: invalid regex secret group 5, max regex secret group 3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			testTranslate(t, tt)
		})
	}
}

func TestTranslateAllowlists(t *testing.T) {
	tests := []translateCase{
		// Global
		{
			cfgName: "valid/allowlist_global_old_compat",
			cfg: Config{
				Rules: map[string]Rule{},
				Allowlists: []*Allowlist{
					{
						StopWords: []string{"0989c462-69c9-49fa-b7d2-30dc5c576a97"},
					},
				},
			},
		},
		{
			cfgName: "valid/allowlist_global_multiple",
			cfg: Config{
				Rules: map[string]Rule{
					"test": {
						RuleID:   "test",
						Regex:    regexp.MustCompile(`token = "(.+)"`),
						Keywords: []string{},
						Tags:     []string{},
					},
				},
				Allowlists: []*Allowlist{
					{
						Regexes: []*regexp.Regexp{regexp.MustCompile("^changeit$")},
					},
					{
						MatchCondition: AllowlistMatchAnd,
						Paths:          []*regexp.Regexp{regexp.MustCompile("^node_modules/.*")},
						StopWords:      []string{"mock"},
					},
				},
			},
		},
		{
			cfgName: "valid/allowlist_global_target_rules",
			cfg: Config{
				Rules: map[string]Rule{
					"github-app-token": {
						RuleID:   "github-app-token",
						Regex:    regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`),
						Tags:     []string{},
						Keywords: []string{},
						Allowlists: []*Allowlist{
							{
								Paths: []*regexp.Regexp{regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`)},
							},
						},
					},
					"github-oauth": {
						RuleID:     "github-oauth",
						Regex:      regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
						Tags:       []string{},
						Keywords:   []string{},
						Allowlists: nil,
					},
					"github-pat": {
						RuleID:   "github-pat",
						Regex:    regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
						Tags:     []string{},
						Keywords: []string{},
						Allowlists: []*Allowlist{
							{
								Paths: []*regexp.Regexp{regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`)},
							},
						},
					},
				},
				Allowlists: []*Allowlist{
					{
						Regexes: []*regexp.Regexp{regexp.MustCompile(".*fake.*")},
					},
				},
			},
		},
		{
			cfgName: "valid/allowlist_global_regex",
			cfg: Config{
				Rules: map[string]Rule{},
				Allowlists: []*Allowlist{
					{
						MatchCondition: AllowlistMatchOr,
						Regexes:        []*regexp.Regexp{regexp.MustCompile("AKIALALEM.L33243OLIA")},
					},
				},
			},
		},
		{
			cfgName:   "invalid/allowlist_global_empty",
			cfg:       Config{},
			wantError: errors.New("[[allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords"),
		},
		{
			cfgName:   "invalid/allowlist_global_old_and_new",
			cfg:       Config{},
			wantError: errors.New("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]"),
		},
		{
			cfgName:   "invalid/allowlist_global_target_rule_id",
			cfg:       Config{},
			wantError: errors.New("[[allowlists]] target rule ID 'github-pat' does not exist"),
		},
		{
			cfgName:   "invalid/allowlist_global_regextarget",
			cfg:       Config{},
			wantError: errors.New("[[allowlists]] unknown allowlist |regexTarget| 'mtach' (expected 'match', 'line')"),
		},

		// Rule
		{
			cfgName: "valid/allowlist_rule_old_compat",
			cfg: Config{
				Rules: map[string]Rule{"example": {
					RuleID:   "example",
					Regex:    regexp.MustCompile(`example\d+`),
					Tags:     []string{},
					Keywords: []string{},
					Allowlists: []*Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Regexes:        []*regexp.Regexp{regexp.MustCompile("123")},
						},
					},
				}},
			},
		},
		{
			cfgName: "valid/allowlist_rule_regex",
			cfg: Config{
				Title: "simple config with allowlist for aws",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []*Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Regexes:        []*regexp.Regexp{regexp.MustCompile("AKIALALEMEL33243OLIA")},
						},
					},
				}},
			},
		},
		{
			cfgName: "valid/allowlist_rule_commit",
			cfg: Config{
				Title: "simple config with allowlist for a specific commit",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []*Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Commits:        []string{"allowthiscommit"},
						},
					},
				}},
			},
		},
		{
			cfgName: "valid/allowlist_rule_path",
			cfg: Config{
				Title: "simple config with allowlist for .go files",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []*Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Paths:          []*regexp.Regexp{regexp.MustCompile(".go")},
						},
					},
				}},
			},
		},
		{
			cfgName:   "invalid/allowlist_rule_empty",
			cfg:       Config{},
			wantError: errors.New("example: [[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords"),
		},
		{
			cfgName:   "invalid/allowlist_rule_old_and_new",
			cfg:       Config{},
			wantError: errors.New("example: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]"),
		},
		{
			cfgName:   "invalid/allowlist_rule_regextarget",
			cfg:       Config{},
			wantError: errors.New("example: [[rules.allowlists]] unknown allowlist |regexTarget| 'mtach' (expected 'match', 'line')"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			testTranslate(t, tt)
		})
	}
}

func TestTranslateExtend(t *testing.T) {
	tests := []translateCase{
		// Valid
		{
			cfgName: "valid/extend",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-access-key": {
						RuleID:      "aws-access-key",
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					"aws-secret-key": {
						RuleID:      "aws-secret-key",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
					"aws-secret-key-again": {
						RuleID:      "aws-secret-key-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_disabled",
			cfg: Config{
				Title: "gitleaks extend disable",
				Rules: map[string]Rule{
					"aws-secret-key": {
						RuleID:   "aws-secret-key",
						Regex:    regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:     []string{"key", "AWS"},
						Keywords: []string{},
					},
					"pypi-upload-token": {
						RuleID:   "pypi-upload-token",
						Regex:    regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
						Tags:     []string{},
						Keywords: []string{},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_no_regexpath",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []*Allowlist{
							{
								Description:    "False positive. Keys used for colors match the rule, and should be excluded.",
								MatchCondition: AllowlistMatchOr,
								Paths:          []*regexp.Regexp{regexp.MustCompile(`something.py`)},
							},
						},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_description",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's description",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "Puppy Doggy",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_path",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's path",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Path:        regexp.MustCompile("(?:puppy)"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_regex",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's regex",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:a)"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_secret_group",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's secretGroup",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:a)(?:a)"),
					SecretGroup: 2,
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_entropy",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's entropy",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Entropy:     999.0,
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_keywords",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's keywords",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{"puppy"},
					Tags:        []string{"key", "AWS"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_override_tags",
			rules:   []string{"aws-access-key"},
			cfg: Config{
				Title: "override a built-in rule's tags",
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS", "puppy"},
				},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_allowlist_or",
			cfg: Config{
				Title: "gitleaks extended 3",
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []*Allowlist{
							{
								MatchCondition: AllowlistMatchOr,
								StopWords:      []string{"fake"},
							},
							{
								MatchCondition: AllowlistMatchOr,
								Commits:        []string{"abcdefg1"},
								Paths:          []*regexp.Regexp{regexp.MustCompile(`ignore\.xaml`)},
								Regexes:        []*regexp.Regexp{regexp.MustCompile(`foo.+bar`)},
								RegexTarget:    "line",
								StopWords:      []string{"example"},
							},
						},
					},
				},
			},
		},
		{
			cfgName: "valid/extend_rule_allowlist_and",
			cfg: Config{
				Title: "gitleaks extended 3",
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []*Allowlist{
							{
								MatchCondition: AllowlistMatchOr,
								StopWords:      []string{"fake"},
							},
							{
								MatchCondition: AllowlistMatchAnd,
								Commits:        []string{"abcdefg1"},
								Paths:          []*regexp.Regexp{regexp.MustCompile(`ignore\.xaml`)},
								Regexes:        []*regexp.Regexp{regexp.MustCompile(`foo.+bar`)},
								RegexTarget:    "line",
								StopWords:      []string{"example"},
							},
						},
					},
				},
			},
		},

		// Invalid
	}

	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			testTranslate(t, tt)
		})
	}
}

func testTranslate(t *testing.T, test translateCase) {
	t.Helper()
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})

	viper.AddConfigPath(configPath)
	viper.SetConfigName(test.cfgName)
	viper.SetConfigType("toml")
	err := viper.ReadInConfig()
	require.NoError(t, err)

	var vc ViperConfig
	err = viper.Unmarshal(&vc)
	require.NoError(t, err)
	cfg, err := vc.Translate()
	if err != nil && !assert.EqualError(t, err, test.wantError.Error()) {
		return
	}

	if len(test.rules) > 0 {
		rules := make(map[string]Rule)
		for _, name := range test.rules {
			rules[name] = cfg.Rules[name]
		}
		cfg.Rules = rules
	}

	opts := cmp.Options{
		cmp.Comparer(regexComparer),
		cmpopts.IgnoreUnexported(Rule{}, Allowlist{}),
	}
	if diff := cmp.Diff(test.cfg.Title, cfg.Title); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", test.cfgName, diff)
	}
	if diff := cmp.Diff(test.cfg.Rules, cfg.Rules, opts); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", test.cfgName, diff)
	}
	if diff := cmp.Diff(test.cfg.Allowlists, cfg.Allowlists, opts); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", test.cfgName, diff)
	}
}

func TestExtendedRuleKeywordsAreDowncase(t *testing.T) {
	tests := []struct {
		name             string
		cfgName          string
		expectedKeywords string
	}{
		{
			name:             "Extend base rule that includes AWS keyword with new attribute",
			cfgName:          "valid/extend_base_rule_including_keywords_with_attribute",
			expectedKeywords: "aws",
		},
		{
			name:             "Extend base with a new rule with CMS keyword",
			cfgName:          "valid/extend_rule_new",
			expectedKeywords: "cms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				viper.Reset()
			})

			viper.AddConfigPath(configPath)
			viper.SetConfigName(tt.cfgName)
			viper.SetConfigType("toml")
			err := viper.ReadInConfig()
			require.NoError(t, err)

			var vc ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)
			cfg, err := vc.Translate()
			require.NoError(t, err)

			_, exists := cfg.Keywords[tt.expectedKeywords]
			require.Truef(t, exists, "The expected keyword %s did not exist as a key of cfg.Keywords", tt.expectedKeywords)
		})
	}
}
