package detect

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		cfgName          string
		fragment         Fragment
		findings         []report.Finding
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName: "validate",
			fragment: Fragment{
				Raw:      `dont matter`,
				FilePath: "tmp.go",
			},
			findings: []report.Finding{
				{
					Match:  os.Getenv("GITHUB_TOKEN"),
					Secret: os.Getenv("GITHUB_TOKEN"),
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
				{
					Match:  "ghp_1234567890abcdefghzzzz",
					Secret: "ghp_1234567890abcdefghzzzz",
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
			},
			expectedFindings: []report.Finding{
				{
					Match:  "ghp_1234567890abcdefghijjj",
					Secret: "ghp_1234567890abcdefghijjj",
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
			},
		},
		// {
		// 	cfgName: "validate",
		// 	fragment: Fragment{
		// 		Raw:      `dont matter`,
		// 		FilePath: "tmp.go",
		// 	},
		// 	findings: []report.Finding{
		// 		{
		// 			Match:  "adobbe-id-1",
		// 			Secret: "adobbe-id-1",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-id",
		// 		},
		// 		{
		// 			Match:  "adobbe-id-2",
		// 			Secret: "adobbe-id-2",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-id",
		// 		},
		// 		{
		// 			Match:  "adobbe-key-1",
		// 			Secret: "adobbe-key-1",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-project-key",
		// 		},
		// 		{
		// 			Match:  "adobbe-key-2",
		// 			Secret: "adobbe-key-2",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-project-key",
		// 		},
		// 	},
		// 	expectedFindings: []report.Finding{
		// 		{
		// 			Match:  "ghp_1234567890abcdefghijjj",
		// 			Secret: "ghp_1234567890abcdefghijjj",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "github-pat",
		// 		},
		// 	},
		// },
	}

	for _, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
		assert.Equal(t, tt.wantError, err)
		d := NewDetector(cfg)

		d.Verify(tt.findings)
		// assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func Test_HelperFuncs(t *testing.T) {
	tests := []struct {
		name       string
		helperFunc func(s string) string
		input      string
		want       string
	}{
		{
			name:       "base64",
			helperFunc: HelperFunctions.Base64Encode,
			input:      `Basic ${base64("admin:a3375993-e848-4c65-be66-d0274ea37bde")}`,
			want:       `Basic YWRtaW46YTMzNzU5OTMtZTg0OC00YzY1LWJlNjYtZDAyNzRlYTM3YmRl`,
		},
		{
			name:       "urlEncode",
			helperFunc: HelperFunctions.UrlEncode,
			input:      `https://example.com?client_secret=${urlEncode("j@515$%9012!")}`,
			want:       `https://example.com?client_secret=j%40515%24%259012%21`,
		},
		// TODO: Add more test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.helperFunc(tt.input), "encodeBase64(%v)", tt.input)
		})
	}
}

func Test_expandUrlPlaceholders(t *testing.T) {
	type args struct {
		url             string
		requiredIDs     map[string]struct{}
		finding         report.Finding
		secretsByRuleID map[string]map[string]struct{}
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		// This should never happen.
		{
			name: "no placeholders",
			args: args{
				url: "https://example.com/foo?bar=baz",
			},
			want: []string{"https://example.com/foo?bar=baz"},
		},
		{
			name: "one placeholder, one finding",
			args: args{
				url: "https://example.com/foo?key=${rule-id}",
				finding: report.Finding{
					RuleID: "rule-id",
					Secret: "s3cr3t",
				},
			},
			want: []string{"https://example.com/foo?key=s3cr3t"},
		},
		{
			name: "one placeholder, many findings",
			args: args{
				url: "https://example.com/foo?key=${rule-id}",
				finding: report.Finding{
					RuleID: "rule-id",
					Secret: "s3cr3t",
				},
				// These shouldn't be used.
				secretsByRuleID: map[string]map[string]struct{}{
					"rule-id": {
						"changeme1": {},
						"changeme2": {},
					},
				},
			},
			want: []string{"https://example.com/foo?key=s3cr3t"},
		},
		{
			name: "many placeholders, missing finding",
			args: args{
				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{},
			},
			wantErr: fmt.Errorf("no results for required rule: secret-rule"),
		},
		{
			name: "many placeholders, one finding",
			args: args{
				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr3t": {},
					},
				},
			},
			want: []string{"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t"},
		},
		{
			name: "many placeholders, many findings",
			args: args{
				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr3t-1": {},
						"s3cr3t_2": {},
					},
				},
			},
			want: []string{
				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t-1",
				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t_2",
			},
		},
		{
			name: "many placeholders, excessive findings",
			args: args{
				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr1t": {},
						"s3cr2t": {},
						"s3cr3t": {},
						"s3cr4t": {},
					},
				},
			},
			wantErr: fmt.Errorf("excessive number of results for required rule: secret-rule"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := expandUrlPlaceholders(tt.args.url, tt.args.requiredIDs, &tt.args.finding, tt.args.secretsByRuleID, map[string]string{})
			if tt.wantErr != nil {
				assert.Equal(t, err.Error(), tt.wantErr.Error())
			} else {
				require.NoError(t, err)
				assert.ElementsMatchf(t, tt.want, actual, "expandUrlPlaceholders(%v, %v)", tt.args.url, tt.args.requiredIDs)
			}
		})
	}
}

func Test_expandHeaderPlaceholders(t *testing.T) {
	type args struct {
		headers         map[string]string
		requiredIDs     map[string]struct{}
		finding         report.Finding
		secretsByRuleID map[string]map[string]struct{}
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]string
		wantErr error
	}{
		// This should never happen.
		{
			name: "no placeholders",
			args: args{
				headers: map[string]string{
					"Accept": "application/json",
				},
			},
			want: map[string][]string{
				"Accept": {"application/json"},
			},
		},
		{
			name: "one placeholder, one finding",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"api-key:${rule-id}\")}",
				},
				finding: report.Finding{
					RuleID: "rule-id",
					Secret: "s3cr3t",
				},
			},
			want: map[string][]string{
				"Authorization": {`Basic ${base64("api-key:s3cr3t")}`},
			},
		},
		{
			name: "one placeholder, many findings",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"api-key:${rule-id}\")}",
				},
				finding: report.Finding{
					RuleID: "rule-id",
					Secret: "s3cr3t",
				},
				// These shouldn't be used.
				secretsByRuleID: map[string]map[string]struct{}{
					"rule-id": {
						"changeme1": {},
						"changeme2": {},
					},
				},
			},
			want: map[string][]string{
				"Authorization": {`Basic ${base64("api-key:s3cr3t")}`},
			},
		},
		{
			name: "many placeholders, missing finding",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
				},
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{},
			},
			wantErr: fmt.Errorf("no results for required rule: secret-rule"),
		},
		{
			name: "many placeholders, one finding",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
				},
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr3t": {},
					},
				},
			},
			want: map[string][]string{
				"Authorization": {`Basic ${base64("gitleaks:s3cr3t")}`},
			},
		},
		{
			name: "many placeholders, many findings",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
				},
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr3t-1": {},
						"s3cr3t_2": {},
					},
				},
			},
			want: map[string][]string{
				"Authorization": {`Basic ${base64("gitleaks:s3cr3t-1")}`, `Basic ${base64("gitleaks:s3cr3t_2")}`},
			},
		},
		{
			name: "many placeholders, excessive findings",
			args: args{
				headers: map[string]string{
					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
				},
				requiredIDs: map[string]struct{}{
					"secret-rule": {},
				},
				finding: report.Finding{
					RuleID: "id-rule",
					Secret: "gitleaks",
				},
				secretsByRuleID: map[string]map[string]struct{}{
					"secret-rule": {
						"s3cr1t": {},
						"s3cr2t": {},
						"s3cr3t": {},
						"s3cr4t": {},
					},
				},
			},
			wantErr: fmt.Errorf("excessive number of results for required rule: secret-rule"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := expandHeaderPlaceholders(tt.args.headers, tt.args.requiredIDs, &tt.args.finding, tt.args.secretsByRuleID, map[string]string{})
			if tt.wantErr != nil {
				assert.Equal(t, err.Error(), tt.wantErr.Error())
			} else {
				require.NoError(t, err)
				// https://stackoverflow.com/a/67624073
				less := func(a, b string) bool { return a < b }
				if diff := cmp.Diff(tt.want, actual, cmpopts.SortSlices(less)); diff != "" {
					t.Errorf("diff: (-want +got)\n%s", diff)
				}
			}
		})
	}
}
