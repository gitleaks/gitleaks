package report

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	expectPath = "../testdata/expected/"
	tmpPath    = "../testdata/tmp"
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
		tmpfile, err := os.Create(filepath.Join(tmpPath, strconv.Itoa(i)+test.ext))
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		err = Write(test.findings, config.Config{}, test.ext, tmpfile.Name())
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		got, err := os.ReadFile(tmpfile.Name())
		if err != nil {
			os.Remove(tmpfile.Name())
			t.Error(err)
		}
		os.Remove(tmpfile.Name())

		if len(got) == 0 && !test.wantEmpty {
			t.Errorf("got empty file with extension " + test.ext)
		}

		if test.wantEmpty {
			if len(got) > 0 {
				t.Errorf("Expected empty file, got %s", got)
			}
			continue
		}
	}
}
