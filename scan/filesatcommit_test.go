package scan_test

import (
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

func TestFilesAtCommitScan(t *testing.T) {
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
			description: "basic repo with no secrets present in files at first commit",
			opts: options.Options{
				Path:          filepath.Join(repoBasePath, "basic"),
				Report:        filepath.Join(expectPath, "basic", "results_files_at_ae8db4a2.json.got"),
				ReportFormat:  "json",
				FilesAtCommit: "ae8db4a2306798fcb3a5b9cbe8c486027fc1931f",
			},
			empty: true,
		},
		{
			description: "basic repo with secrets present in files at third commit",
			opts: options.Options{
				Path:          filepath.Join(repoBasePath, "basic"),
				Report:        filepath.Join(expectPath, "basic", "results_files_at_208ae46.json.got"),
				ReportFormat:  "json",
				FilesAtCommit: "208ae4669ade2563fcaf9f12922fa2c0a5b37c63",
			},
			wantPath: filepath.Join(expectPath, "basic", "results_files_at_208ae46.json"),
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
