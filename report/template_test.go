package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTemplate(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
	}{
		{
			testReportName: "markdown",
			expected:       filepath.Join(expectPath, "report", "template_markdown.md"),
			findings: []Finding{
				{

					RuleID:      "test-rule",
					Description: "A test rule",
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
					Tags:        []string{"tag1", "tag2", "tag3"},
				},
			},
		},
		{
			testReportName: "jsonextra",
			expected:       filepath.Join(expectPath, "report", "template_jsonextra.json"),
			findings: []Finding{
				{

					RuleID:      "test-rule",
					Description: "A test rule",
					Line:        "whole line containing secret",
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
					Tags:        []string{"tag1", "tag2", "tag3"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			reporter, err := NewTemplateReporter(templatePath + test.testReportName + ".tmpl")
			require.NoError(t, err)

			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+filepath.Ext(test.expected)))
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
		})
	}
}
