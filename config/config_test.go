package config

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config/flags"
	"regexp"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Rules: map[string]Rule{"aws-access-key": {
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					Report:      true,
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
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					Report:      true,
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
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Regex:       regexp.MustCompile("(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
					Tags:        []string{"key", "AWS"},
					Keywords:    []string{},
					Report:      true,
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
					RuleID:      "discord-api-key",
					Description: "Discord API key",
					Regex:       regexp.MustCompile(`(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]`),
					Allowlist:   Allowlist{},
					Entropy:     3.5,
					SecretGroup: 3,
					Tags:        []string{},
					Keywords:    []string{},
					Report:      true,
				},
				},
			},
		},
		{
			cfgName:   "missing_id",
			cfg:       Config{},
			wantError: fmt.Errorf("rule |id| is missing or empty, regex: (?i)(discord[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([a-h0-9]{64})['\\\"]"),
		},
		//{
		//	cfgName:   "no_regex_or_path",
		//	cfg:       Config{},
		//	wantError: fmt.Errorf("discord-api-key: both |regex| and |path| are empty, this rule will have no effect"),
		//},
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
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						Report:      true,
					},
					"aws-secret-key": {
						RuleID:      "aws-secret-key",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						Report:      true,
					},
					"aws-secret-key-again": {
						RuleID:      "aws-secret-key-again",
						Description: "AWS Secret Key",
						Regex:       regexp.MustCompile(`(?i)aws_(.{0,20})?=?.[\'\"0-9a-zA-Z\/+]{40}`),
						Tags:        []string{"key", "AWS"},
						Keywords:    []string{},
						Report:      true,
					},
				},
			},
		},
		// Verify
		{
			cfgName:   "verify_no_placeholders",
			cfg:       Config{},
			wantError: fmt.Errorf("azure-client-secret: verify config does not contain a placeholder for the rule's output (${azure-client-secret})"),
		},
		{
			cfgName:   "verify_multipart_invalid_requires",
			cfg:       Config{},
			wantError: fmt.Errorf("rule ID 'azure-client-id' required by '[azure-client-secret]' does not exist"),
		},
	}

	// Required for verification tests to work.
	flags.EnableExperimentalVerification.Store(true)
	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			viper.Reset()
			viper.AddConfigPath(configPath)
			viper.SetConfigName(tt.cfgName)
			viper.SetConfigType("toml")
			err := viper.ReadInConfig()
			require.NoError(t, err)

			var vc ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)
			cfg, err := vc.Translate()
			assert.Equal(t, tt.wantError, err)
			assert.Equal(t, cfg.Rules, tt.cfg.Rules)
		})
	}
}

func Test_parseVerify(t *testing.T) {
	tests := []struct {
		cfgName   string
		verify    Verify
		wantError error
	}{
		{
			cfgName: "verify_multipart_header",
			verify: Verify{
				requiredIDs: map[string]struct{}{
					"github-client-id": {},
				},
				HTTPVerb: "GET",
				URL:      "https://api.github.com/rate_limit",
				staticHeaders: map[string]string{
					"Accept":               "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				dynamicHeaders: map[string]string{
					"Authorization": "Basic ${base64(\"${github-client-id}:${github-client-secret}\")}",
				},
				ExpectedStatus: []string{"200"},
			},
		},
		{
			cfgName: "verify_multipart_query",
			verify: Verify{
				requiredIDs: map[string]struct{}{
					"github-client-id": {},
				},
				HTTPVerb:         "GET",
				URL:              "https://api.github.com/rate_limit?client_id=${github-client-id}&client_secret=${github-client-secret}",
				placeholderInUrl: true,
				staticHeaders: map[string]string{
					"Accept":               "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				ExpectedStatus: []string{"200"},
			},
		},
	}

	flags.EnableExperimentalVerification.Store(true)
	for _, tt := range tests {
		t.Run(tt.cfgName, func(t *testing.T) {
			viper.Reset()
			viper.AddConfigPath(configPath)
			viper.SetConfigName(tt.cfgName)
			viper.SetConfigType("toml")
			err := viper.ReadInConfig()
			require.NoError(t, err)

			var vc ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)
			cfg, err := vc.Translate()

			var actual Verify
			for _, rule := range cfg.Rules {
				if rule.Verify.URL == "" {
					continue
				}
				actual = rule.Verify
				break
			}

			// Lazy hack to avoid duplicate declaration for Headers.
			if tt.verify.Headers == nil {
				tt.verify.Headers = map[string]string{}
				for k, v := range tt.verify.staticHeaders {
					tt.verify.Headers[k] = v
				}
				for k, v := range tt.verify.dynamicHeaders {
					tt.verify.Headers[k] = v
				}
			}

			assert.Equal(t, tt.wantError, err)
			assert.Equal(t, tt.verify, actual)
		})
	}
}
