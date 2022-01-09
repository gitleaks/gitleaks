package config

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const configPath = "../testdata/config/"

func TestTranslate(t *testing.T) {
	tests := []struct {
		cfgName   string
		cfg       Config
		wantError error
	}{
		{
			cfgName: "allow_aws_re",
			cfg: Config{
				Rules: []*Rule{
					{
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
						Tags:        []string{"key", "AWS"},
						Examples:    []string{},
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
				Rules: []*Rule{
					{
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
						Tags:        []string{"key", "AWS"},
						Examples:    []string{},
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
				Rules: []*Rule{
					{
						Description: "AWS Access Key",
						Regex:       regexp.MustCompile("(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
						Tags:        []string{"key", "AWS"},
						Examples:    []string{},
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
				Rules: []*Rule{
					{
						Description: "Discord API key",
						Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
						RuleID:      "discord-api-key",
						Allowlist:   Allowlist{},
						Entropy:     3.5,
						SecretGroup: 3,
						Tags:        []string{},
						Examples:    []string{},
					},
				},
			},
		},
		{
			cfgName:   "bad_entropy_group",
			cfg:       Config{},
			wantError: fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
	}

	for _, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc ViperConfig
		viper.Unmarshal(&vc)
		cfg, err := vc.Translate()
		if tt.wantError != nil {
			if err == nil {
				t.Errorf("expected error")
			}
			assert.Equal(t, tt.wantError, err)
		}

		assert.Equal(t, cfg.Rules, tt.cfg.Rules)
	}
}

func TestIncludeEntropy(t *testing.T) {
	tests := []struct {
		rule    Rule
		secret  string
		entropy float32
		include bool
	}{
		{
			rule: Rule{
				RuleID:      "generic-api-key",
				SecretGroup: 4,
				Entropy:     3.5,
				Regex:       regexp.MustCompile(`(?i)((key|api|token|secret|password)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]`),
			},
			secret:  `e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5`,
			entropy: 3.7906235872459746,
			include: true,
		},
		{
			rule: Rule{
				RuleID:      "generic-api-key",
				SecretGroup: 4,
				Entropy:     4,
				Regex:       regexp.MustCompile(`(?i)((key|api|token|secret|password)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]`),
			},
			secret:  `e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5`,
			entropy: 3.7906235872459746,
			include: false,
		},
		{
			rule: Rule{
				RuleID:      "generic-api-key",
				SecretGroup: 4,
				Entropy:     3.0,
				Regex:       regexp.MustCompile(`(?i)((key|api|token|secret|password)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]`),
			},
			secret:  `ssh-keyboard-interactive`,
			entropy: 0,
			include: false,
		},
	}

	for _, tt := range tests {
		include, entropy := tt.rule.IncludeEntropy(tt.secret)
		assert.Equal(t, true, tt.rule.EntropySet())
		assert.Equal(t, tt.entropy, float32(entropy))
		assert.Equal(t, tt.include, include)
	}
}
