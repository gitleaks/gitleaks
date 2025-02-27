package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJunit(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "junit_simple.xml"),
			findings: []Finding{
				{

					Description: "Test Rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Tags:        []string{},
				},
				{

					Description: "Test Rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   2,
					EndLine:     3,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "",
					File:        "auth.py",
					Commit:      "",
					Author:      "",
					Email:       "",
					Date:        "",
					Tags:        []string{},
				},
			},
		},
		{
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "junit_empty.xml"),
			findings:       []Finding{},
		},
	}

	reporter := JunitReporter{}
	for _, test := range tests {
		tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".xml"))
		require.NoError(t, err)
		defer tmpfile.Close()

		err = reporter.Write(tmpfile, test.findings)
		require.NoError(t, err)
		assert.FileExists(t, tmpfile.Name())

		got, err := os.ReadFile(tmpfile.Name())
		require.NoError(t, err)
		if test.wantEmpty {
			assert.Empty(t, got)
			return
		}

		want, err := os.ReadFile(test.expected)
		require.NoError(t, err)

		wantStr := lineEndingReplacer.Replace(string(want))
		gotStr := lineEndingReplacer.Replace(string(got))
		assert.Equal(t, wantStr, gotStr)
	}
}
