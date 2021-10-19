package scan_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

const repoBasePath = "../testdata/repos/"
const expectPath = "../testdata/expect/"

func TestScan(t *testing.T) {
	err := moveDotGit("dotGit", ".git")
	if err != nil {
		t.Fatal(err)
	}
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description string
		opts        options.Options
		wantPath    string
	}{
		{
			description: "test google api key leak AND square oauth leak",
			opts: options.Options{
				Path:         filepath.Join(repoBasePath, "with_square_and_google"),
				Report:       filepath.Join(expectPath, "results_square_and_google.json.got"),
				ReportFormat: "json",
				NoGit:				true,
			},
			wantPath: filepath.Join(expectPath, "results_square_and_google.json"),
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

		if test.wantPath != "" {
			err := fileCheck(test.wantPath, test.opts.Report)
			if err != nil {
				t.Error(test.description, err)
			}
		}
	}
}


func moveDotGit(from, to string) error {
	repoDirs, err := ioutil.ReadDir("../testdata/repos")
	if err != nil {
		return err
	}
	for _, dir := range repoDirs {
		if to == ".git" {
			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
			if os.IsNotExist(err) {
				// dont want to delete the only copy of .git accidentally
				continue
			}
			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
		}
		if !dir.IsDir() {
			continue
		}
		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
		if os.IsNotExist(err) {
			continue
		}

		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
		if err != nil {
			return err
		}
	}
	return nil
}

func fileCheck(wantPath, gotPath string) error {
	var (
		gotLeaks  []scan.Leak
		wantLeaks []scan.Leak
	)
	want, err := ioutil.ReadFile(wantPath)
	if err != nil {
		return err
	}

	got, err := ioutil.ReadFile(gotPath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(got, &gotLeaks)
	if err != nil {
		return err
	}

	err = json.Unmarshal(want, &wantLeaks)
	if err != nil {
		return err
	}

	if len(wantLeaks) != len(gotLeaks) {
		return fmt.Errorf("got %d leaks, want %d leaks", len(gotLeaks), len(wantLeaks))
	}

	for _, wantLeak := range wantLeaks {
		found := false
		for _, gotLeak := range gotLeaks {
			if same(gotLeak, wantLeak) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unable to find %+v in %s", wantLeak, gotPath)
		}
	}

	if err := os.Remove(gotPath); err != nil {
		return err
	}
	return nil
}

func same(l1, l2 scan.Leak) bool {
	if l1.Commit != l2.Commit {
		return false
	}

	if l1.Offender != l2.Offender {
		return false
	}

	if l1.OffenderEntropy != l2.OffenderEntropy {
		return false
	}

	if l1.Line != l2.Line {
		return false
	}

	if l1.Tags != l2.Tags {
		return false
	}

	if l1.LineNumber != l2.LineNumber {
		return false
	}

	if l1.Author != l2.Author {
		return false
	}

	if l1.LeakURL != l2.LeakURL {
		return false
	}

	if l1.RepoURL != l2.RepoURL {
		return false
	}

	if l1.Repo != l2.Repo {
		return false
	}
	return true

}
