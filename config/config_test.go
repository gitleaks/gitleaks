package config

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

const configPath = "../testdata/config/"

func TestTranslate(t *testing.T) {
	tests := []struct {
		// Configuration file basename to load, from `../testdata/config/`.
		cfgName string
		// Expected result.
		cfg Config
		// Rules to compare.
		rules []string
		// Error to expect.
		wantError error
	}{
		{
			cfgName: "allowlist_old_compat",
			cfg: Config{
				Rules: map[string]Rule{"example": {
					RuleID:   "example",
					Regex:    regexp.MustCompile(`example\d+`),
					Tags:     []string{},
					Keywords: []string{},
					Allowlists: []Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Regexes:        []*regexp.Regexp{regexp.MustCompile("123")},
						},
					},
				}},
			},
		},
		{
			cfgName:   "allowlist_invalid_empty",
			cfg:       Config{},
			wantError: fmt.Errorf("example: [[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords"),
		},
		{
			cfgName:   "allowlist_invalid_old_and_new",
			cfg:       Config{},
			wantError: fmt.Errorf("example: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]"),
		},
		{
			cfgName:   "allowlist_invalid_regextarget",
			cfg:       Config{},
			wantError: fmt.Errorf("example: unknown allowlist |regexTarget| 'mtach' (expected 'match', 'line')"),
		},
		{
			cfgName: "allow_aws_re",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Regexes:        []*regexp.Regexp{regexp.MustCompile("AKIALALEMEL33243OLIA")},
						},
					},
				}},
			},
		},
		{
			cfgName: "allow_commit",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Commits:        []string{"allowthiscommit"},
						},
					},
				}},
			},
		},
		{
			cfgName: "allow_path",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Keywords:    []string{},
					Tags:        []string{"key", "AWS"},
					Allowlists: []Allowlist{
						{
							MatchCondition: AllowlistMatchOr,
							Paths:          []*regexp.Regexp{regexp.MustCompile(".go")},
						},
					},
				}},
			},
		},
		{
			cfgName: "entropy_group",
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
		{
			cfgName:   "missing_id",
			cfg:       Config{},
			wantError: fmt.Errorf("rule |id| is missing or empty, regex: (?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{64})['\\\"]"),
		},
		{
			cfgName:   "no_regex_or_path",
			cfg:       Config{},
			wantError: fmt.Errorf("discord-api-key: both |regex| and |path| are empty, this rule will have no effect"),
		},
		{
			cfgName:   "bad_entropy_group",
			cfg:       Config{},
			wantError: fmt.Errorf("discord-api-key: invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "base",
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
			cfgName: "extend_rule_allowlist_or",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []Allowlist{
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
			cfgName: "extend_rule_allowlist_and",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []Allowlist{
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
		{
			cfgName: "extend_empty_regexpath",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Keywords:    []string{},
						Tags:        []string{"key", "AWS"},
						Allowlists: []Allowlist{
							{
								MatchCondition: AllowlistMatchOr,
								Paths:          []*regexp.Regexp{regexp.MustCompile(`something.py`)},
							},
						},
					},
				},
			},
		},
		{
			cfgName: "override_description",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_entropy",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_secret_group",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_regex",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_path",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_tags",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "override_keywords",
			rules:   []string{"aws-access-key"},
			cfg: Config{
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
			cfgName: "extend_disabled",
			cfg: Config{
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
	}

	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			t.Cleanup(func() {
				extendDepth = 0
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
			if err != nil && !assert.EqualError(t, tt.wantError, err.Error()) {
				return
			}

			if len(tt.rules) > 0 {
				rules := make(map[string]Rule)
				for _, name := range tt.rules {
					rules[name] = cfg.Rules[name]
				}
				cfg.Rules = rules
			}

			var regexComparer = func(x, y *regexp.Regexp) bool {
				if x == nil || y == nil {
					return x == y
				}
				return x.String() == y.String()
			}
			opts := cmp.Options{cmp.Comparer(regexComparer)}
			if diff := cmp.Diff(tt.cfg.Rules, cfg.Rules, opts); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", tt.cfgName, diff)
			}
		})
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
			cfgName:          "extend_base_rule_including_keysword_with_attribute",
			expectedKeywords: "aws",
		},
		{
			name:             "Extend base with a new rule with CMS keyword",
			cfgName:          "extend_with_new_rule",
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
