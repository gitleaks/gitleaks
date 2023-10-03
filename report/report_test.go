package report

import (
	"os"
	"path/filepath"
	"strconv"
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

	for i, test := range tests {
		t.Run(test.ext, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), strconv.Itoa(i)+test.ext))
			require.NoError(t, err)
			err = Write(test.findings, config.Config{}, test.ext, tmpfile.Name())
			require.NoError(t, err)
			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())
			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}
			assert.NotEmpty(t, got)
		})
	}
}
