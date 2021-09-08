package scan

import (
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
)

func TestCommitScan(t *testing.T) {
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
			description: "empty repo",
			opts: options.Options{
				Path:   filepath.Join(repoBasePath, "empty"),
				Report: filepath.Join(expectPath, "empty", "empty_report.json.got"),
			},
			empty: true,
		},
		{
			description: "empty repo with commits option",
			opts: options.Options{
				Path:    filepath.Join(repoBasePath, "empty"),
				Report:  filepath.Join(expectPath, "empty", "empty_report.json.got"),
				Commits: "a,b,c",
			},
			empty: true,
		},
		{
			description: "basic repo with default config at specific commit",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "basic"),
				Report:       filepath.Join(expectPath, "basic", "results_208ae46.json.got"),
				ReportFormat: "json",
                Commit: "208ae4669ade2563fcaf9f12922fa2c0a5b37c63",
			},
			wantPath: filepath.Join(expectPath, "basic", "results_208ae46.json"),
		},
	}

	for _, test := range tests {
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		scanner, err := NewScanner(test.opts, cfg)
		if err != nil {
			t.Error(test.description, err)
		}

		scannerReport, err := scanner.Scan()
		if err != nil {
			t.Fatal(test.description, err)
		}

		err = WriteReport(scannerReport, test.opts, cfg)
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
