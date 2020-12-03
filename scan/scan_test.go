package scan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/zricethezav/gitleaks/v7/report"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/sergi/go-diff/diffmatchpatch"
)

const testRepoBase = "../test_data/test_repos/"

func TestScan(t *testing.T) {
	moveDotGit("dotGit", ".git")
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description string
		opts        options.Options
		wantPath    string
		wantErr     error
		wantScanErr error
		emptyRepo   bool
		wantEmpty   bool
	}{
		{
			description: "test local repo one aws leak",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_local_repo_one_aws_leak.json.got",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak.json",
		},
		{
			description: "test local repo one aws leak threaded",
			opts: options.Options{
				Threads:      runtime.GOMAXPROCS(0),
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_local_repo_one_aws_leak.json.got",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak.json",
		},
		{
			description: "test non existent repo",
			opts: options.Options{
				Path:         "../test_data/test_repos/no_repo_here",
				ReportFormat: "json",
			},
			wantErr:   fmt.Errorf("stat ../test_data/test_repos/no_repo_here: no such file or directory"),
			emptyRepo: true,
		},
		{
			description: "test local repo one aws leak allowlisted",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				ReportFormat: "json",
				ConfigPath:   "../test_data/test_configs/aws_key_allowlist_python_files.toml",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo two leaks",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks.json.got",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_two_leaks.json",
		},
		{
			description: "test local repo two leaks from Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks_commit_from.json.got",
				ReportFormat: "json",
				CommitFrom:   "996865bb912f3bc45898a370a13aadb315014b55",
			},
			wantPath: "../test_data/test_local_repo_two_leaks_commit_from.json",
		},
		{
			description: "test local repo two leaks to Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks_commit_to.json.got",
				ReportFormat: "json",
				CommitTo:     "996865bb912f3bc45898a370a13aadb315014b55",
			},
			wantPath: "../test_data/test_local_repo_two_leaks_commit_to.json",
		},
		{
			description: "test local repo two leaks to from Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks_commit_to_from.json.got",
				ReportFormat: "json",
				CommitFrom:   "d8ac0b73aeeb45843319cdc5ce506516eb49bf7a",
				CommitTo:     "51f6dcf6b89b93f4075ba92c400b075631a6cc93",
			},
			wantPath: "../test_data/test_local_repo_two_leaks_commit_to_from.json",
		},
		{
			description: "test local repo two leaks list Commits",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks_commit_range.json.got",
				ReportFormat: "json",
				Commits:      "d8ac0b73aeeb45843319cdc5ce506516eb49bf7a,996865bb912f3bc45898a370a13aadb315014b55,17471a5fda722a9e423f1a0d3f0d267ea009d41c,51f6dcf6b89b93f4075ba92c400b075631a6cc93,b10b3e2cb320a8c211fda94c4567299d37de7776",
			},
			wantPath: "../test_data/test_local_repo_two_leaks_commit_range.json",
		},
		{
			description: "test local repo two leaks file list commits",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_leaks_file_commit_range.json.got",
				ReportFormat: "json",
				CommitsFile:  "../test_data/test_options/test_local_repo_commits.txt",
			},
			wantPath: "../test_data/test_local_repo_two_leaks_file_commit_range.json",
		},
		{
			description: "test local repo two leaks globally allowlisted",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				ConfigPath:   "../test_data/test_configs/aws_key_global_allowlist_file.toml",
				ReportFormat: "json",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo two leaks allowlisted",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				ConfigPath:   "../test_data/test_configs/aws_key_allowlist_files.toml",
				ReportFormat: "json",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo three leaks dev branch with reportGroup set",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_3",
				Report:       "../test_data/test_local_repo_three_leaks_with_report_groups.json.got",
				ConfigPath:   "../test_data/test_configs/aws_key_with_report_groups.toml",
				Branch:       "dev",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_three_leaks_with_report_groups.json",
		},
		{
			description: "test local repo three leaks dev branch",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_3",
				Report:       "../test_data/test_local_repo_three_leaks.json.got",
				ConfigPath:   "../test_data/test_configs/aws_key.toml",
				Branch:       "dev",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_three_leaks.json",
		},
		{
			description: "test local repo branch does not exist",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_3",
				Branch:       "nobranch",
				ReportFormat: "json",
			},
			wantScanErr: fmt.Errorf("could not find branch nobranch"),
		},
		{
			description: "test local repo one aws leak single Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_local_repo_one_aws_leak_commit.json.got",
				Commit:       "6557c92612d3b35979bd426d429255b3bf9fab74",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak_commit.json",
		},
		{
			description: "test local repo one aws leak AND leak on python files",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_local_repo_one_aws_leak_and_file_leak.json.got",
				ConfigPath:   "../test_data/test_configs/aws_key_file_regex.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak_and_file_leak.json",
		},
		{
			description: "test owner path",
			opts: options.Options{
				Path:         "../test_data/test_repos/",
				Report:       "../test_data/test_local_owner_aws_leak.json.got",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_owner_aws_leak.json",
		},
		{
			description: "test owner path allowlist repo",
			opts: options.Options{
				Path:         "../test_data/test_repos/",
				Report:       "../test_data/test_local_owner_aws_leak_allowlist_repo.json.got",
				ReportFormat: "json",
				ConfigPath:   "../test_data/test_configs/aws_key_local_owner_allowlist_repo.toml",
			},
			wantPath: "../test_data/test_local_owner_aws_leak_allowlist_repo.json",
		},
		{
			description: "test entropy and regex",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_regex_entropy.json.got",
				ConfigPath:   "../test_data/test_configs/regex_entropy.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_regex_entropy.json",
		},
		{
			description: "test local repo four entropy alternative config",
			opts: options.Options{
				Path:           "../test_data/test_repos/test_repo_4",
				Report:         "../test_data/test_local_repo_four_alt_config_entropy.json.got",
				RepoConfigPath: "gitleaks.toml",
				ReportFormat:   "json",
			},
			wantPath: "../test_data/test_local_repo_four_alt_config_entropy.json",
		},
		{
			description: "test local repo four entropy alternative config",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_regex_allowlist.json.got",
				ConfigPath:   "../test_data/test_configs/aws_key_aws_allowlisted.toml",
				ReportFormat: "json",
			},
			wantEmpty: true,
		},
		{
			description: "test owner path depth=2",
			opts: options.Options{
				Path:         "../test_data/test_repos/",
				Report:       "../test_data/test_local_owner_aws_leak_depth_2.json.got",
				ReportFormat: "json",
				Depth:        2,
			},
			wantPath: "../test_data/test_local_owner_aws_leak_depth_2.json",
		},
		{
			description: "test local repo five files at Commit",
			opts: options.Options{
				Path:          "../test_data/test_repos/test_repo_5",
				Report:        "../test_data/test_local_repo_five_files_at_commit.json.got",
				FilesAtCommit: "a4c9fb737d5552fd96fce5cc7eedb23353ba9ed0",
				ReportFormat:  "json",
			},
			wantPath: "../test_data/test_local_repo_five_files_at_commit.json",
		},
		{
			description: "test local repo five files at latest Commit",
			opts: options.Options{
				Path:          "../test_data/test_repos/test_repo_5",
				Report:        "../test_data/test_local_repo_five_files_at_latest_commit.json.got",
				FilesAtCommit: "latest",
				ReportFormat:  "json",
			},
			wantPath: "../test_data/test_local_repo_five_files_at_commit.json",
		},
		{
			description: "test local repo five at Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_5",
				Report:       "../test_data/test_local_repo_five_commit.json.got",
				Commit:       "a4c9fb737d5552fd96fce5cc7eedb23353ba9ed0",
				ReportFormat: "json",
				ConfigPath:   "../test_data/test_configs/generic.toml",
			},
			wantPath: "../test_data/test_local_repo_five_commit.json",
		},
		{
			description: "test local repo five at latest Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_5",
				Report:       "../test_data/test_local_repo_five_at_latest_commit.json.got",
				Commit:       "latest",
				ReportFormat: "json",
				ConfigPath:   "../test_data/test_configs/generic.toml",
			},
			wantPath: "../test_data/test_local_repo_five_at_latest_commit.json",
		},
		{
			description: "test local repo six filename",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_filename.json.got",
				ConfigPath:   "../test_data/test_configs/regex_filename.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_six_filename.json",
		},
		{
			description: "test local repo six filepath",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_filepath.json.got",
				ConfigPath:   "../test_data/test_configs/regex_filepath.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_six_filepath.json",
		},
		{
			description: "test local repo six filename and filepath",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_filepath_filename.json.got",
				ConfigPath:   "../test_data/test_configs/regex_filepath_filename.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_six_filepath_filename.json",
		},
		{
			description: "test local repo six path globally allowlisted",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_path_globally_allowlisted.json.got",
				ConfigPath:   "../test_data/test_configs/aws_key_global_allowlist_path.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_six_path_globally_allowlisted.json",
		},
		{
			description: "test local repo six leaks since date",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_leaks_since_date.json.got",
				ReportFormat: "json",
				CommitSince:  "2019-10-25",
			},
			wantPath: "../test_data/test_local_repo_six_leaks_since_date.json",
		},
		{
			description: "test local repo two leaks until date",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_6",
				Report:       "../test_data/test_local_repo_six_leaks_until_date.json.got",
				ReportFormat: "json",
				CommitUntil:  "2019-10-25",
			},
			wantPath: "../test_data/test_local_repo_six_leaks_until_date.json",
		},
		{
			description: "test local repo four leaks timerange Commit",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_4",
				Report:       "../test_data/test_local_repo_four_leaks_commit_timerange.json.got",
				ReportFormat: "json",
				CommitSince:  "2019-10-25T13:01:27-0400",
				CommitUntil:  "2019-10-25T13:12:32-0400",
			},
			wantPath: "../test_data/test_local_repo_four_leaks_commit_timerange.json",
		},
		{
			description: "test local repo two allowlist Commit config",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_2",
				Report:       "../test_data/test_local_repo_two_allowlist_commits.json.got",
				ConfigPath:   "../test_data/test_configs/allowlist_commit.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_two_allowlist_commits.json",
		},
		{
			description: "test local repo eight (merges)",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_8",
				Report:       "../test_data/test_local_repo_eight.json.got",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_eight.json",
		},
		{
			description: "test local repo nine",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_9",
				Report:       "../test_data/test_local_repo_nine_aws_leak.json.got",
				ConfigPath:   "../test_data/test_configs/large_with_global_allowlist_regex.toml",
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_nine_aws_leak.json",
		},
		{
			description: "test dir one no git",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_dir_1",
				Report:       "../test_data/test_dir1_aws_leak.json.got",
				ReportFormat: "json",
				NoGit:        true,
			},
			wantPath: "../test_data/test_dir1_aws_leak.json",
		},
		{
			description: "test file with leak no git",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_dir_1/server.test.py",
				Report:       "../test_data/test_file1_aws_leak.json.got",
				ReportFormat: "json",
				NoGit:        true,
			},
			wantPath: "../test_data/test_file1_aws_leak.json",
		},
	}

	for _, test := range tests {
		fmt.Println(test.description)
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		scanner, err := NewScanner(test.opts, cfg)
		if test.wantErr != nil {
			if err == nil {
				t.Fatalf("did not receive wantErr: %v", test.wantErr)
			}
			if err.Error() != test.wantErr.Error() {
				t.Fatalf("wantErr does not equal err received: %v", err.Error())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		scannerReport, err := scanner.Scan()

		if test.wantScanErr != nil {
			if err == nil {
				t.Fatalf("did not receive wantErr: %v", test.wantScanErr)
			}
			if err.Error() != test.wantScanErr.Error() {
				t.Fatalf("wantErr does not equal err received: %v", err.Error())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		err = report.WriteReport(scannerReport, test.opts, cfg)
		if err != nil {
			t.Error(err)
		}

		if test.wantEmpty {
			if len(scannerReport.Leaks) != 0 {
				t.Errorf("wanted no leaks but got some instead: %+v", scannerReport.Leaks)
			}
			continue
		}

		if test.wantPath != "" {
			err := fileCheck(test.wantPath, test.opts.Report)
			if err != nil {
				t.Error(err)
			}
		}
	}
}

//
func TestScanUncommited(t *testing.T) {
	moveDotGit("dotGit", ".git")
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description  string
		opts         options.Options
		wantPath     string
		wantErr      error
		wantScanErr  error
		emptyRepo    bool
		wantEmpty    bool
		fileToChange string
		addition     string
	}{
		{
			description: "test scan local one leak",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Report:       "../test_data/test_local_repo_one_aws_leak_uncommitted.json.got",
				Unstaged:     true,
				ReportFormat: "json",
			},
			wantPath:     "../test_data/test_local_repo_one_aws_leak_uncommitted.json",
			fileToChange: "server.test.py",
			addition:     " aws_access_key_id='AKIAIO5FODNN7DXAMPLE'\n\n",
		},
		{
			description: "test scan local no leak",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_1",
				Unstaged:     true,
				ReportFormat: "json",
			},
			wantEmpty:    true,
			fileToChange: "server.test.py",
			addition:     "nothing bad",
		},
		{
			description: "test scan repo with no commits",
			opts: options.Options{
				Path:         "../test_data/test_repos/test_repo_7",
				Report:       "../test_data/test_local_repo_seven_aws_leak_uncommitted.json.got",
				Unstaged:     true,
				ReportFormat: "json",
			},
			wantPath: "../test_data/test_local_repo_seven_aws_leak_uncommitted.json",
		},
	}
	for _, test := range tests {
		var (
			old []byte
			err error
		)
		fmt.Println(test.description)
		if test.fileToChange != "" {
			old, err = ioutil.ReadFile(fmt.Sprintf("%s/%s", test.opts.Path, test.fileToChange))
			if err != nil {
				t.Error(err)
			}
			altered, err := os.OpenFile(fmt.Sprintf("%s/%s", test.opts.Path, test.fileToChange),
				os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				t.Error(err)
			}

			_, err = altered.WriteString(test.addition)
			if err != nil {
				t.Error(err)
			}

		}

		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}
		scanner, err := NewScanner(test.opts, cfg)
		if test.wantErr != nil {
			if err == nil {
				t.Fatalf("did not receive wantErr: %v", test.wantErr)
			}
			if err.Error() != test.wantErr.Error() {
				t.Fatalf("wantErr does not equal err received: %v", err.Error())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		scannerReport, err := scanner.Scan()

		if test.wantScanErr != nil {
			if err == nil {
				t.Fatalf("did not receive wantErr: %v", test.wantScanErr)
			}
			if err.Error() != test.wantScanErr.Error() {
				t.Fatalf("wantErr does not equal err received: %v", err.Error())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		err = report.WriteReport(scannerReport, test.opts, cfg)
		if err != nil {
			t.Error(err)
		}

		if test.fileToChange != "" {
			err = ioutil.WriteFile(fmt.Sprintf("%s/%s", test.opts.Path, test.fileToChange), old, 0)
			if err != nil {
				t.Error(err)
			}
		}

		if test.wantEmpty {
			continue
		}

		if test.wantPath != "" {
			err := fileCheck(test.wantPath, test.opts.Report)
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func fileCheck(wantPath, gotPath string) error {
	var (
		gotLeaks  []report.Leak
		wantLeaks []report.Leak
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

	sort.Slice(gotLeaks, func(i, j int) bool { return (gotLeaks)[i].Commit < (gotLeaks)[j].Commit })
	sort.Slice(wantLeaks, func(i, j int) bool { return (wantLeaks)[i].Commit < (wantLeaks)[j].Commit })

	if !reflect.DeepEqual(gotLeaks, wantLeaks) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(want), string(got), false)
		return fmt.Errorf("%s does not equal %s: %s", wantPath, gotPath, dmp.DiffPrettyText(diffs))
	}
	if err := os.Remove(gotPath); err != nil {
		return err
	}
	return nil
}

func moveDotGit(from, to string) error {
	repoDirs, err := ioutil.ReadDir("../test_data/test_repos")
	if err != nil {
		return err
	}
	for _, dir := range repoDirs {
		if !dir.IsDir() {
			continue
		}
		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", testRepoBase, dir.Name(), from))
		if os.IsNotExist(err) {
			continue
		}

		err = os.Rename(fmt.Sprintf("%s/%s/%s", testRepoBase, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", testRepoBase, dir.Name(), to))
		if err != nil {
			return err
		}
	}
	return nil
}
