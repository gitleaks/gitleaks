package detect

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("no DoFunc defined")
}

func LoadConfig(t *testing.T, configFileName string) config.Config {
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(configFileName)
	viper.SetConfigType("toml")
	err := viper.ReadInConfig()
	require.NoError(t, err)

	var vc config.ViperConfig
	err = viper.Unmarshal(&vc)
	require.NoError(t, err)
	cfg, err := vc.Translate()
	require.NoError(t, err)

	return cfg
}

func TestVerify(t *testing.T) {
	// Prepare mock responses
	mockResponses := map[string]*http.Response{
		"https://api.github.com/rate_limit": {
			StatusCode: 200,
			Body:       ioutil.NopCloser(strings.NewReader(`{"rate": {"limit": 5000}}`)),
		},
	}

	// Create a mock HTTP client
	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			resp, ok := mockResponses[req.URL.String()]
			if !ok {
				return &http.Response{
					StatusCode: 404,
					Body:       ioutil.NopCloser(strings.NewReader("Not Found")),
				}, nil
			}
			return resp, nil
		},
	}

	// Initialize Detector with the mock client
	detector := &Detector{
		HTTPClient:  mockClient,
		VerifyCache: *NewRequestCache(),
	}

	tests := []struct {
		name       string
		findings   []report.Finding
		configName string
		want       []report.Finding
	}{
		{
			name:       "no findings",
			findings:   []report.Finding{},
			configName: "verify_multipart_header.toml",
			want:       []report.Finding{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LoadConfig(t, tt.configName)
			detector.Config = cfg
			verifiedFindings := detector.Verify(tt.findings)
			assert.Equal(t, tt.want, verifiedFindings)
		})
	}

	// Call the Verify function

}

// func Test_expandUrlPlaceholders(t *testing.T) {
// 	type args struct {
// 		url             string
// 		requiredIDs     map[string]struct{}
// 		finding         report.Finding
// 		secretsByRuleID map[string]map[string]struct{}
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    []string
// 		wantErr error
// 	}{
// 		// This should never happen.
// 		{
// 			name: "no placeholders",
// 			args: args{
// 				url: "https://example.com/foo?bar=baz",
// 			},
// 			want: []string{"https://example.com/foo?bar=baz"},
// 		},
// 		{
// 			name: "one placeholder, one finding",
// 			args: args{
// 				url: "https://example.com/foo?key=${rule-id}",
// 				finding: report.Finding{
// 					RuleID: "rule-id",
// 					Secret: "s3cr3t",
// 				},
// 			},
// 			want: []string{"https://example.com/foo?key=s3cr3t"},
// 		},
// 		{
// 			name: "one placeholder, many findings",
// 			args: args{
// 				url: "https://example.com/foo?key=${rule-id}",
// 				finding: report.Finding{
// 					RuleID: "rule-id",
// 					Secret: "s3cr3t",
// 				},
// 				// These shouldn't be used.
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"rule-id": {
// 						"changeme1": {},
// 						"changeme2": {},
// 					},
// 				},
// 			},
// 			want: []string{"https://example.com/foo?key=s3cr3t"},
// 		},
// 		{
// 			name: "many placeholders, missing finding",
// 			args: args{
// 				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{},
// 			},
// 			wantErr: fmt.Errorf("no results for required rule: secret-rule"),
// 		},
// 		{
// 			name: "many placeholders, one finding",
// 			args: args{
// 				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr3t": {},
// 					},
// 				},
// 			},
// 			want: []string{"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t"},
// 		},
// 		{
// 			name: "many placeholders, many findings",
// 			args: args{
// 				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr3t-1": {},
// 						"s3cr3t_2": {},
// 					},
// 				},
// 			},
// 			want: []string{
// 				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t-1",
// 				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t_2",
// 			},
// 		},
// 		{
// 			name: "many placeholders, excessive findings",
// 			args: args{
// 				url: "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr1t": {},
// 						"s3cr2t": {},
// 						"s3cr3t": {},
// 						"s3cr4t": {},
// 					},
// 				},
// 			},
// 			wantErr: fmt.Errorf("excessive number of results for required rule: secret-rule"),
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			actual, err := expandUrlPlaceholders(tt.args.url, tt.args.requiredIDs, &tt.args.finding, tt.args.secretsByRuleID, map[string]string{})
// 			if tt.wantErr != nil {
// 				assert.Equal(t, err.Error(), tt.wantErr.Error())
// 			} else {
// 				require.NoError(t, err)
// 				assert.ElementsMatchf(t, tt.want, actual, "expandUrlPlaceholders(%v, %v)", tt.args.url, tt.args.requiredIDs)
// 			}
// 		})
// 	}
// }

// func Test_expandHeaderPlaceholders(t *testing.T) {
// 	type args struct {
// 		headers         map[string]string
// 		requiredIDs     map[string]struct{}
// 		finding         report.Finding
// 		secretsByRuleID map[string]map[string]struct{}
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    map[string][]string
// 		wantErr error
// 	}{
// 		// This should never happen.
// 		{
// 			name: "no placeholders",
// 			args: args{
// 				headers: map[string]string{
// 					"Accept": "application/json",
// 				},
// 			},
// 			want: map[string][]string{
// 				"Accept": {"application/json"},
// 			},
// 		},
// 		{
// 			name: "one placeholder, one finding",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"api-key:${rule-id}\")}",
// 				},
// 				finding: report.Finding{
// 					RuleID: "rule-id",
// 					Secret: "s3cr3t",
// 				},
// 			},
// 			want: map[string][]string{
// 				"Authorization": {`Basic ${base64("api-key:s3cr3t")}`},
// 			},
// 		},
// 		{
// 			name: "one placeholder, many findings",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"api-key:${rule-id}\")}",
// 				},
// 				finding: report.Finding{
// 					RuleID: "rule-id",
// 					Secret: "s3cr3t",
// 				},
// 				// These shouldn't be used.
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"rule-id": {
// 						"changeme1": {},
// 						"changeme2": {},
// 					},
// 				},
// 			},
// 			want: map[string][]string{
// 				"Authorization": {`Basic ${base64("api-key:s3cr3t")}`},
// 			},
// 		},
// 		{
// 			name: "many placeholders, missing finding",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
// 				},
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{},
// 			},
// 			wantErr: fmt.Errorf("no results for required rule: secret-rule"),
// 		},
// 		{
// 			name: "many placeholders, one finding",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
// 				},
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr3t": {},
// 					},
// 				},
// 			},
// 			want: map[string][]string{
// 				"Authorization": {`Basic ${base64("gitleaks:s3cr3t")}`},
// 			},
// 		},
// 		{
// 			name: "many placeholders, many findings",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
// 				},
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr3t-1": {},
// 						"s3cr3t_2": {},
// 					},
// 				},
// 			},
// 			want: map[string][]string{
// 				"Authorization": {`Basic ${base64("gitleaks:s3cr3t-1")}`, `Basic ${base64("gitleaks:s3cr3t_2")}`},
// 			},
// 		},
// 		{
// 			name: "many placeholders, excessive findings",
// 			args: args{
// 				headers: map[string]string{
// 					"Authorization": "Basic ${base64(\"${id-rule}:${secret-rule}\")}",
// 				},
// 				requiredIDs: map[string]struct{}{
// 					"secret-rule": {},
// 				},
// 				finding: report.Finding{
// 					RuleID: "id-rule",
// 					Secret: "gitleaks",
// 				},
// 				secretsByRuleID: map[string]map[string]struct{}{
// 					"secret-rule": {
// 						"s3cr1t": {},
// 						"s3cr2t": {},
// 						"s3cr3t": {},
// 						"s3cr4t": {},
// 					},
// 				},
// 			},
// 			wantErr: fmt.Errorf("excessive number of results for required rule: secret-rule"),
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			actual, err := expandHeaderPlaceholders(tt.args.headers, tt.args.requiredIDs, &tt.args.finding, tt.args.secretsByRuleID, map[string]string{})
// 			if tt.wantErr != nil {
// 				assert.Equal(t, err.Error(), tt.wantErr.Error())
// 			} else {
// 				require.NoError(t, err)
// 				// https://stackoverflow.com/a/67624073
// 				less := func(a, b string) bool { return a < b }
// 				if diff := cmp.Diff(tt.want, actual, cmpopts.SortSlices(less)); diff != "" {
// 					t.Errorf("diff: (-want +got)\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
