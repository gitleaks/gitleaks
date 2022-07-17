package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	for _, test := range tests {
		// create tmp file using os.TempDir()
		tmpfile, err := os.Create(filepath.Join(tmpPath, test.testReportName+".xml"))
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		err = writeJunit(test.findings, tmpfile)
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		got, err := os.ReadFile(tmpfile.Name())
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		if test.wantEmpty {
			if len(got) > 0 {
				os.Remove(tmpfile.Name())
				t.Errorf("Expected empty file, got %s", got)
			}
			os.Remove(tmpfile.Name())
			continue
		}
		want, err := os.ReadFile(test.expected)
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}

		if string(got) != string(want) {
			err = os.WriteFile(strings.Replace(test.expected, ".xml", ".got.xml", 1), got, 0644)
			if err != nil {
				t.Error(err)
			}
			t.Errorf("got %s, want %s", string(got), string(want))
		}

		os.Remove(tmpfile.Name())
	}
}
