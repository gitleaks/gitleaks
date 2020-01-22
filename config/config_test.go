package config

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v3/options"
	"regexp"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		description   string
		opts          options.Options
		wantErr       error
		wantFileRegex *regexp.Regexp
		wantMessages  *regexp.Regexp
		wantWhitelist Whitelist
	}{
		{
			description: "default config",
			opts:        options.Options{},
		},
		{
			description: "test successful load",
			opts: options.Options{
				Config: "../test_data/test_configs/aws_key.toml",
			},
		},
		{
			description: "test bad toml",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_aws_key.toml",
			},
			wantErr: fmt.Errorf("Near line 7 (last key parsed 'rules.description'): expected value but found \"AWS\" instead"),
		},
		{
			description: "test bad regex",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_regex_aws_key.toml",
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: invalid nested repetition operator: `???`"),
		},
		{
			description: "test bad global whitelist file regex",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_aws_key_global_whitelist_file.toml",
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: missing argument to repetition operator: `??`"),
		},
		{
			description: "test bad global file regex",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_aws_key_file_regex.toml",
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: missing argument to repetition operator: `??`"),
		},
		{
			description: "test bad global message regex",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_aws_key_message_regex.toml",
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: missing argument to repetition operator: `??`"),
		},
		{
			description: "test successful load big ol thing",
			opts: options.Options{
				Config: "../test_data/test_configs/large.toml",
			},
		},
		{
			description: "test load entropy",
			opts: options.Options{
				Config: "../test_data/test_configs/entropy.toml",
			},
		},
		{
			description: "test entropy bad range",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_entropy_1.toml",
			},
			wantErr: fmt.Errorf("entropy range must be ascending"),
		},
		{
			description: "test entropy value p2",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_entropy_2.toml",
			},
			wantErr: fmt.Errorf("strconv.ParseFloat: parsing \"x\": invalid syntax"),
		},
		{
			description: "test entropy value p1",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_entropy_3.toml",
			},
			wantErr: fmt.Errorf("strconv.ParseFloat: parsing \"x\": invalid syntax"),
		},
		{
			description: "test entropy value p1",
			opts: options.Options{
				Config: "../test_data/test_configs/bad_entropy_4.toml",
			},
			wantErr: fmt.Errorf("invalid entropy ranges, must be within 0.0-8.0"),
		},
	}

	for _, test := range tests {
		_, err := NewConfig(test.opts)
		if err != nil {
			if test.wantErr == nil {
				t.Error(err)
			} else if test.wantErr.Error() != err.Error() {
				t.Errorf("expected err: %s, got %s", test.wantErr, err)
			}
		}
	}
}
