package scan_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

func TestUnstaged(t *testing.T) {
	err := moveDotGit("dotGit", ".git")
	if err != nil {
		t.Fatal(err)
	}
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description  string
		opts         options.Options
		wantPath     string
		fileToChange string
		change       string
		empty        bool
	}{
		{
			description: "basic repo with unstagged change containing a secret",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "basic"),
				Report:       filepath.Join(expectPath, "basic", "results_unstaged.json.got"),
				ReportFormat: "json",
				Unstaged:     true,
			},
			wantPath:     filepath.Join(expectPath, "basic", "results_unstaged.json"),
			fileToChange: filepath.Join(repoBasePath, "basic", "secrets.py"),
			change:       "\nadded_aws_access_key_id='AKIAIO5FODNN7DXAMPLE'\n",
		},
		{
			description: "basic repo with unstagged change not containing a secret",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "basic"),
				Report:       filepath.Join(expectPath, "basic", "results_unstaged.json.got"),
				ReportFormat: "json",
				Unstaged:     true,
			},
			empty:        true,
			fileToChange: filepath.Join(repoBasePath, "basic", "secrets.py"),
			change:       "\nnice_variable='is_nice''\n",
		},
	}

	for _, test := range tests {
		var old []byte
		if test.fileToChange != "" {
			old, err = ioutil.ReadFile(test.fileToChange)
			if err != nil {
				t.Error(err)
			}
			altered, err := os.OpenFile(test.fileToChange,
				os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				t.Error(err)
			}

			_, err = altered.WriteString(test.change)
			if err != nil {
				t.Error(err)
			}
		}

		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		scanner, err := scan.NewScanner(test.opts, cfg)
		if err != nil {
			t.Fatal(test.description, err)
		}

		scannerReport, err := scanner.Scan()
		if err != nil {
			t.Fatal(test.description, err)
		}

		err = scan.WriteReport(scannerReport, test.opts, cfg)
		if err != nil {
			t.Error(test.description, err)
		}

		if test.empty {
			if len(scannerReport.Leaks) != 0 {
				t.Errorf("%s wanted no leaks but got some instead: %+v", test.description, scannerReport.Leaks)
			}
		}

		if test.wantPath != "" {
			err := fileCheck(test.wantPath, test.opts.Report)
			if err != nil {
				t.Error(test.description, err)
			}
		}
		err = ioutil.WriteFile(test.fileToChange, old, 0)
		if err != nil {
			t.Error(err)
		}

	}
}
