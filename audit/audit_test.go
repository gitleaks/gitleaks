package audit

import (
	"fmt"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/zricethezav/gitleaks/config"
	"github.com/zricethezav/gitleaks/manager"
	"github.com/zricethezav/gitleaks/options"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"
)

const testRepoBase = "../test_data/test_repos/"

func TestAudit(t *testing.T) {
	moveDotGit("dotGit", ".git")
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description string
		opts        options.Options
		wantPath    string
		wantErr     error
		emptyRepo   bool
		wantEmpty   bool
	}{
		{
			description: "test local repo one aws leak",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_local_repo_one_aws_leak.json.got",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak.json",
		},
		{
			description: "test local repo one aws leak threaded",
			opts: options.Options{
				Threads:  runtime.GOMAXPROCS(0),
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_local_repo_one_aws_leak.json.got",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak.json",
		},
		{
			description: "test non existent repo",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/no_repo_here",
			},
			emptyRepo: true,
		},
		{
			description: "test local repo one aws leak whitelisted",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Config:   "../test_data/test_configs/aws_key_whitelist_python_files.toml",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo two leaks",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_2",
				Report:   "../test_data/test_local_repo_two_leaks.json.got",
			},
			wantPath: "../test_data/test_local_repo_two_leaks.json",
		},
		{
			description: "test local repo two leaks globally whitelisted",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_2",
				Config:   "../test_data/test_configs/aws_key_global_whitelist_file.toml",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo two leaks whitelisted",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_2",
				Config:   "../test_data/test_configs/aws_key_whitelist_files.toml",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo three leaks dev branch",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_3",
				Report:   "../test_data/test_local_repo_three_leaks.json.got",
				Config:   "../test_data/test_configs/aws_key.toml",
				Branch:   "dev",
			},
			wantPath: "../test_data/test_local_repo_three_leaks.json",
		},
		{
			description: "test local repo branch does not exist",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_3",
				Branch:   "nobranch",
			},
			wantEmpty: true,
		},
		{
			description: "test local repo one aws leak single commit",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_local_repo_one_aws_leak_commit.json.got",
				Commit:   "6557c92612d3b35979bd426d429255b3bf9fab74",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak_commit.json",
		},
		{
			description: "test local repo one aws leak AND leak on python files",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_local_repo_one_aws_leak_and_file_leak.json.got",
				Config:   "../test_data/test_configs/aws_key_file_regex.toml",
			},
			wantPath: "../test_data/test_local_repo_one_aws_leak_and_file_leak.json",
		},
		{
			description: "test owner path",
			opts: options.Options{
				OwnerPath: "../test_data/test_repos/",
				Report:    "../test_data/test_local_owner_aws_leak.json.got",
			},
			wantPath: "../test_data/test_local_owner_aws_leak.json",
		},
		{
			description: "test entropy",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_entropy.json.got",
				Config:   "../test_data/test_configs/entropy.toml",
			},
			wantPath: "../test_data/test_entropy.json",
		},
		{
			description: "test entropy and regex",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_regex_entropy.json.got",
				Config:   "../test_data/test_configs/regex_entropy.toml",
			},
			wantPath: "../test_data/test_regex_entropy.json",
		},
		{
			description: "test local repo four entropy alternative config",
			opts: options.Options{
				RepoPath:   "../test_data/test_repos/test_repo_4",
				Report:     "../test_data/test_local_repo_four_alt_config_entropy.json.got",
				RepoConfig: true,
			},
			wantPath: "../test_data/test_local_repo_four_alt_config_entropy.json",
		},
		{
			description: "test local repo four entropy alternative config",
			opts: options.Options{
				RepoPath: "../test_data/test_repos/test_repo_1",
				Report:   "../test_data/test_regex_whitelist.json.got",
				Config:   "../test_data/test_configs/aws_key_aws_whitelisted.toml",
			},
			wantEmpty: true,
		},
	}

	for _, test := range tests {
		fmt.Println(test.description)
		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}

		m, err := manager.NewManager(test.opts, cfg)
		if err != nil {
			t.Error(err)
		}

		err = Run(m)

		if test.wantErr != nil {
			if err == nil {
				t.Errorf("did not receive wantErr: %v", test.wantErr)
			}
			if err.Error() != test.wantErr.Error() {
				t.Errorf("wantErr does not equal err received: %v", err.Error())
			}
			continue
		}

		err = m.Report()

		if test.wantEmpty {
			if len(m.GetLeaks()) != 0 {
				t.Errorf("wanted no leaks but got some instead: %+v", m.GetLeaks())
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

func TestAuditUncommited(t *testing.T) {
	moveDotGit("dotGit", ".git")
	defer moveDotGit(".git", "dotGit")
	tests := []struct {
		description  string
		opts         options.Options
		wantPath     string
		wantErr      error
		emptyRepo    bool
		wantEmpty    bool
		fileToChange string
		addition     string
	}{
		{
			description: "test audit local one leak",
			opts: options.Options{
				RepoPath:   "../test_data/test_repos/test_repo_1",
				Report:     "../test_data/test_local_repo_one_aws_leak_uncommitted.json.got",
				Uncommited: true,
			},
			wantPath:     "../test_data/test_local_repo_one_aws_leak_uncommitted.json",
			fileToChange: "server.test.py",
			addition:     " aws_access_key_id='AKIAIO5FODNN7DXAMPLE'\n\n",
		},
		{
			description: "test audit local no leak",
			opts: options.Options{
				RepoPath:   "../test_data/test_repos/test_repo_1",
				Uncommited: true,
			},
			wantEmpty:    true,
			fileToChange: "server.test.py",
			addition:     "nothing bad",
		},
	}
	for _, test := range tests {
		fmt.Println(test.description)
		old, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", test.opts.RepoPath, test.fileToChange))
		if err != nil {
			t.Error(err)
		}
		altered, err := os.OpenFile(fmt.Sprintf("%s/%s", test.opts.RepoPath, test.fileToChange),
			os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			t.Error(err)
		}

		_, err = altered.WriteString(test.addition)
		if err != nil {
			t.Error(err)
		}

		cfg, err := config.NewConfig(test.opts)
		if err != nil {
			t.Error(err)
		}
		m, err := manager.NewManager(test.opts, cfg)
		if err != nil {
			t.Error(err)
		}

		if err := Run(m); err != nil {
			t.Error(err)
		}

		if err := m.Report(); err != nil {
			t.Error(err)
		}

		err = ioutil.WriteFile(fmt.Sprintf("%s/%s", test.opts.RepoPath, test.fileToChange), old, 0)
		if err != nil {
			t.Error(err)
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
	want, err := ioutil.ReadFile(wantPath)
	if err != nil {
		return err
	}

	got, err := ioutil.ReadFile(gotPath)
	if err != nil {
		return err
	}

	if strings.Trim(string(want), "\n") != strings.Trim(string(got), "\n") {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(want), string(got), false)
		return fmt.Errorf("does not equal: %s", dmp.DiffPrettyText(diffs))
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
		err = os.Rename(fmt.Sprintf("%s/%s/%s", testRepoBase, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", testRepoBase, dir.Name(), to))
		if err != nil {
			return err
		}
	}
	return nil
}
