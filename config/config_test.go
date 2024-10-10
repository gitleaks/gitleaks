package config

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"regexp"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			cfgName: "allow_aws_re",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Regexes: []*regexp.Regexp{
							regexp.MustCompile("AKIALALEMEL33243OLIA"),
						},
					},
				},
				},
			},
		},
		{
			cfgName: "allow_commit",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Commits: []string{"allowthiscommit"},
					},
				},
				},
			},
		},
		{
			cfgName: "allow_path",
			cfg: Config{
				Rules: map[string]Rule{"aws-access-key": {
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					RuleID:      "aws-access-key",
					Allowlist: Allowlist{
						Paths: []*regexp.Regexp{
							regexp.MustCompile(".go"),
						},
					},
				},
				},
			},
		},
		{
			cfgName: "entropy_group",
			cfg: Config{
				Rules: map[string]Rule{"discord-api-key": {
					Description: "Discord API key",
					Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
					RuleID:      "discord-api-key",
					Allowlist:   Allowlist{},
					Entropy:     3.5,
					SecretGroup: 3,
					Tags:        []string{},
					Keywords:    []string{},
				},
				},
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
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-access-key",
					},
					"aws-secret-key": {
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-secret-key",
					},
					"aws-secret-key-again": {
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						RuleID:      "aws-secret-key-again",
					},
				},
			},
		},
		{
			cfgName: "extend_rule_allowlist",
			cfg: Config{
				Rules: map[string]Rule{
					"aws-secret-key-again-again": {
						RuleID:      "aws-secret-key-again-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						Allowlist: Allowlist{
							Commits: []string{"abcdefg1"},
							Regexes: []*regexp.Regexp{
								regexp.MustCompile(`foo.+bar`),
							},
							RegexTarget: "line",
							Paths: []*regexp.Regexp{
								regexp.MustCompile(`ignore\.xaml`),
							},
							StopWords: []string{"example"},
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
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						Allowlist: Allowlist{
							Paths: []*regexp.Regexp{
								regexp.MustCompile(`something.py`),
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
					Entropy:     999.0,
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
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
			if !assert.Equal(t, tt.wantError, err) {
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
				// Compare the string representation of the regex patterns.
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
