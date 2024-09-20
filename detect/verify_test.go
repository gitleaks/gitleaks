package detect

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func Test_expandPlaceholdersInString(t *testing.T) {
	type args struct {
		template                string
		placeholder             string
		secret                  string
		placeholderByRequiredID map[string]string
		secretsByRequiredID     map[string][]string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// This should never happen.
		{
			name: "no placeholders",
			args: args{
				template: "https://example.com/foo?bar=baz",
			},
			want: []string{"https://example.com/foo?bar=baz"},
		},
		{
			name: "one placeholder, one finding",
			args: args{
				template:    "https://example.com/foo?key=${rule-id}",
				placeholder: "${rule-id}",
				secret:      "s3cr3t",
			},
			want: []string{"https://example.com/foo?key=s3cr3t"},
		},
		{
			name: "one placeholder, many findings",
			args: args{
				template:    "https://example.com/foo?key=${rule-id}",
				placeholder: "${rule-id}",
				secret:      "s3cr3t",
				// These shouldn't be used.
				placeholderByRequiredID: map[string]string{
					"rule-id": "${rule-id}",
				},
				secretsByRequiredID: map[string][]string{
					"rule-id": {"changeme"},
				},
			},
			want: []string{"https://example.com/foo?key=s3cr3t"},
		},
		{
			name: "many placeholders, one finding",
			args: args{
				template:    "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				placeholder: "${id-rule}",
				secret:      "gitleaks",
				placeholderByRequiredID: map[string]string{
					"secret-rule": "${secret-rule}",
				},
				secretsByRequiredID: map[string][]string{
					"secret-rule": {"s3cr3t"},
				},
			},
			want: []string{"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t"},
		},
		{
			name: "many placeholders, many findings",
			args: args{
				template:    "https://example.com/foo?key-id=${id-rule}&key-secret=${secret-rule}",
				placeholder: "${id-rule}",
				secret:      "gitleaks",
				placeholderByRequiredID: map[string]string{
					"secret-rule": "${secret-rule}",
				},
				secretsByRequiredID: map[string][]string{
					"secret-rule": {"s3cr3t-1", "s3cr3t_2"},
				},
			},
			want: []string{
				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t-1",
				"https://example.com/foo?key-id=gitleaks&key-secret=s3cr3t_2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := expandPlaceholdersInString(tt.args.template, tt.args.placeholder, tt.args.secret, tt.args.placeholderByRequiredID, tt.args.secretsByRequiredID)
			// https://stackoverflow.com/a/67624073
			less := func(a, b string) bool { return a < b }
			if diff := cmp.Diff(tt.want, actual, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("diff: (-want +got)\n%s", diff)
			}
		})
	}
}
