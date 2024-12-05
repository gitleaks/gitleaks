package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	expectPath = "../testdata/expected/"
)

func TestReport(t *testing.T) {
	tests := []struct {
		findings  []Finding
		ext       string
		wantEmpty bool
	}{
		{
			ext: "json",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: ".json",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: ".jsonj",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
			wantEmpty: true,
		},
		{
			ext: ".csv",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: "csv",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: "CSV",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: ".xml",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		{
			ext: "junit",
			findings: []Finding{
				{
					RuleID: "test-rule",
				},
			},
		},
		// {
		// 	ext: "SARIF",
		// 	findings: []Finding{
		// 		{
		// 			RuleID: "test-rule",
		// 		},
		// 	},
		// },
	}

	for _, test := range tests {
		t.Run(test.ext, func(t *testing.T) {
			buf := testWriter{
				bytes.NewBuffer(nil),
			}
			err := Write(test.findings, config.Config{}, test.ext, buf)
			require.NoError(t, err)
			got := buf.Bytes()
			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}
			assert.NotEmpty(t, got)
		})
	}
}

type testWriter struct {
	*bytes.Buffer
}

func (t testWriter) Close() error {
	return nil
}
