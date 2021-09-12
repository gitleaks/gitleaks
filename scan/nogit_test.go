package scan_test

import (
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

func TestNoGit(t *testing.T) {
	err := moveDotGit("dotGit", ".git")
	if err != nil {
		t.Fatal(err)
	}
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description string
		opts        options.Options
		wantPath    string
		empty       bool
	}{
		{
			description: "[nogit] basic repo",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "basic"),
				Report:       filepath.Join(expectPath, "basic", "results_no_git.json.got"),
				ReportFormat: "json",
				NoGit:        true,
			},
			wantPath: filepath.Join(expectPath, "basic", "results_no_git.json"),
		},
		{
			description: "[nogit] empty",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "empty"),
				Report:       filepath.Join(expectPath, "empty", "results_no_git_empty.json.got"),
				ReportFormat: "json",
				NoGit:        true,
			},
			empty: true,
		},
		{
			description: "[nogit] basic repo multi-line",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "multi"),
				Report:       filepath.Join(expectPath, "multi", "results_no_git_multi.json.got"),
				ReportFormat: "json",
				NoGit:        true,
			},
			wantPath: filepath.Join(expectPath, "multi", "results_no_git_multi.json"),
		},
	}

	for _, test := range tests {
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		scanner, err := scan.NewScanner(test.opts, cfg)
		if err != nil {
			t.Error(test.description, err)
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
			continue
		}

		if test.wantPath != "" {
			err := fileCheck(test.wantPath, test.opts.Report)
			if err != nil {
				t.Error(test.description, err)
			}
		}
	}
}
