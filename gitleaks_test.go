package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/franela/goblin"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

const testWhitelistCommit = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
commits = [
  "eaeffdc65b4c73ccb67e75d96bd8743be2c85973",
]
`
const testWhitelistFile = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
files = [
  ".go",
]
`
const testWhitelistBranch = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
branches = [
  "origin/master",
]
`

const testWhitelistRegex = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
regexes= [
  "AKIA",
]
`

func TestGetRepo(t *testing.T) {
	var err error
	dir, err = ioutil.TempDir("", "gitleaksTestRepo")
	defer os.RemoveAll(dir)
	if err != nil {
		panic(err)
	}
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/gronit",
	})

	if err != nil {
		panic(err)
	}

	var tests = []struct {
		testOpts       Options
		description    string
		expectedErrMsg string
	}{
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/gronit",
			},
			description:    "test plain clone remote repo",
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/gronit",
				Disk: true,
			},
			description:    "test on disk clone remote repo",
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				RepoPath: dir,
			},
			description:    "test local clone repo",
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/nope",
			},
			description:    "test no repo",
			expectedErrMsg: "authentication required",
		},
		{
			testOpts: Options{
				Repo:           "https://github.com/gitleakstest/private",
				IncludePrivate: true,
			},
			description:    "test private repo",
			expectedErrMsg: "invalid auth method",
		},
		{
			testOpts: Options{
				Repo:           "https://github.com/gitleakstest/private",
				IncludePrivate: true,
				Disk:           true,
			},
			description:    "test private repo",
			expectedErrMsg: "invalid auth method",
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestGetRepo", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				_, err := getRepo()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				}
			})
		})
	}
}

func TestGetOwnerRepo(t *testing.T) {
	var err error

	dir, err = ioutil.TempDir("", "gitleaksTestOwner")
	defer os.RemoveAll(dir)
	if err != nil {
		panic(err)
	}
	git.PlainClone(dir+"/gronit", false, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/gronit",
	})
	git.PlainClone(dir+"/h1domains", false, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/h1domains",
	})
	var tests = []struct {
		testOpts       Options
		description    string
		expectedErrMsg string
		numRepos       int
	}{
		{
			testOpts: Options{
				GithubUser: "gitleakstest",
			},
			description:    "test github user",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubUser: "gitleakstest",
				Disk:       true,
			},
			description:    "test github user on disk ",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg: "gitleakstestorg",
			},
			description:    "test github org",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				OwnerPath: dir,
			},
			description:    "test plain clone remote repo",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg:      "gitleakstestorg",
				IncludePrivate: true,
			},
			description:    "test private org no ssh",
			numRepos:       0,
			expectedErrMsg: "no ssh auth available",
		},
		{
			testOpts: Options{
				GithubOrg: "gitleakstestorg",
				Disk:      true,
			},
			description:    "test org on disk",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg:      "gitleakstestorg",
				IncludePrivate: true,
				Disk:           true,
			},
			description:    "test private org on disk no ssh",
			numRepos:       0,
			expectedErrMsg: "no ssh auth available",
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestGetOwnerRepo", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				repos, err := getOwnerRepos()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				}
				g.Assert(len(repos)).Equal(test.numRepos)
			})
		})
	}
}

func TestWriteReport(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "reportDir")
	reportFile := path.Join(tmpDir, "report.json")
	defer os.RemoveAll(tmpDir)
	leaks := []Leak{
		{
			Line:     "eat",
			Commit:   "your",
			Offender: "veggies",
			Type:     "and",
			Message:  "get",
			Author:   "some",
			File:     "sleep",
			Branch:   "thxu",
		},
	}

	var tests = []struct {
		leaks       []Leak
		reportFile  string
		fileName    string
		description string
		testOpts    Options
	}{
		{
			leaks:       leaks,
			reportFile:  reportFile,
			fileName:    "report.json",
			description: "can we write a file",
			testOpts: Options{
				Report: reportFile,
			},
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestWriteReport", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				writeReport(test.leaks)
				f, _ := os.Stat(test.reportFile)
				g.Assert(f.Name()).Equal(test.fileName)
			})
		})
	}

}

func testTomlLoader() string {
	tmpDir, _ := ioutil.TempDir("", "whiteListConfigs")
	ioutil.WriteFile(path.Join(tmpDir, "regex"), []byte(testWhitelistRegex), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "branch"), []byte(testWhitelistBranch), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "commit"), []byte(testWhitelistCommit), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "file"), []byte(testWhitelistFile), 0644)
	return tmpDir
}

func TestAuditRepo(t *testing.T) {
	var leaks []Leak
	err := loadToml()
	configsDir := testTomlLoader()
	defer os.RemoveAll(configsDir)

	if err != nil {
		panic(err)
	}
	leaksRepo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/gronit.git",
	})
	if err != nil {
		panic(err)
	}

	cleanRepo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/h1domains.git",
	})
	if err != nil {
		panic(err)
	}

	var tests = []struct {
		testOpts          Options
		description       string
		expectedErrMsg    string
		numLeaks          int
		repo              *git.Repository
		whiteListFiles    []*regexp.Regexp
		whiteListCommits  map[string]bool
		whiteListBranches []string
		whiteListRegexes  []*regexp.Regexp
		configPath        string
	}{
		{
			repo:        leaksRepo,
			description: "two leaks present",
			numLeaks:    2,
		},
		{
			repo:        leaksRepo,
			description: "two leaks present limit goroutines",
			numLeaks:    2,
			testOpts: Options{
				MaxGoRoutines: 2,
			},
		},
		{
			repo:        leaksRepo,
			description: "audit specific bad branch",
			numLeaks:    2,
			testOpts: Options{
				Branch: "master",
			},
		},
		{
			repo:        leaksRepo,
			description: "audit specific good branch",
			numLeaks:    0,
			testOpts: Options{
				Branch: "dev",
			},
		},
		{
			repo:        leaksRepo,
			description: "audit all branch",
			numLeaks:    6,
			testOpts: Options{
				AuditAllRefs: true,
			},
		},
		{
			repo:        leaksRepo,
			description: "audit all branch whitelist 1",
			numLeaks:    4,
			testOpts: Options{
				AuditAllRefs: true,
			},
			whiteListBranches: []string{
				"origin/master",
			},
		},
		{
			repo:        leaksRepo,
			description: "two leaks present whitelist AWS.. no leaks",
			whiteListRegexes: []*regexp.Regexp{
				regexp.MustCompile("AKIA"),
			},
			numLeaks: 0,
		},
		{
			repo:        leaksRepo,
			description: "two leaks present limit goroutines",
			numLeaks:    2,
		},
		{
			repo:        cleanRepo,
			description: "no leaks present",
			numLeaks:    0,
		},
		{
			repo:        leaksRepo,
			description: "two leaks present whitelist go files",
			whiteListFiles: []*regexp.Regexp{
				regexp.MustCompile(".go"),
			},
			numLeaks: 0,
		},
		{
			repo:        leaksRepo,
			description: "two leaks present whitelist bad commit",
			whiteListCommits: map[string]bool{
				"eaeffdc65b4c73ccb67e75d96bd8743be2c85973": true,
			},
			numLeaks: 1,
		},
		{
			repo:        leaksRepo,
			description: "redact",
			testOpts: Options{
				Redact: true,
			},
			numLeaks: 2,
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist regex",
			configPath:  path.Join(configsDir, "regex"),
			numLeaks:    0,
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist branch",
			configPath:  path.Join(configsDir, "branch"),
			testOpts: Options{
				AuditAllRefs: true,
			},
			numLeaks: 4,
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist file",
			configPath:  path.Join(configsDir, "file"),
			numLeaks:    0,
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist commit",
			configPath:  path.Join(configsDir, "commit"),
			numLeaks:    1,
		},
	}

	whiteListCommits = make(map[string]bool)
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestAuditRepo", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				// settin da globs
				if test.whiteListFiles != nil {
					whiteListFiles = test.whiteListFiles
				} else {
					whiteListFiles = nil
				}
				if test.whiteListCommits != nil {
					whiteListCommits = test.whiteListCommits
				} else {
					whiteListCommits = nil
				}
				if test.whiteListBranches != nil {
					whiteListBranches = test.whiteListBranches
				} else {
					whiteListBranches = nil
				}
				if test.whiteListRegexes != nil {
					whiteListRegexes = test.whiteListRegexes
				} else {
					whiteListRegexes = nil
				}

				// config paths
				if test.configPath != "" {
					os.Setenv("GITLEAKS_CONFIG", test.configPath)
					loadToml()
				}

				leaks, err = auditRepo(test.repo)

				if opts.Redact {
					g.Assert(leaks[0].Offender).Equal("REDACTED")
				}
				g.Assert(len(leaks)).Equal(test.numLeaks)
			})
		})
	}
}

func TestOptionGuard(t *testing.T) {
	var tests = []struct {
		testOpts            Options
		githubToken         bool
		description         string
		expectedErrMsg      string
		expectedErrMsgFuzzy string
	}{
		{
			testOpts:       Options{},
			description:    "default no opts",
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				IncludePrivate: true,
				GithubOrg:      "fakeOrg",
			},
			description:    "private org no githubtoken",
			expectedErrMsg: "user/organization private repos require env var GITHUB_TOKEN to be set",
			githubToken:    false,
		},
		{
			testOpts: Options{
				IncludePrivate: true,
				GithubUser:     "fakeUser",
			},
			description:    "private user no githubtoken",
			expectedErrMsg: "user/organization private repos require env var GITHUB_TOKEN to be set",
			githubToken:    false,
		},
		{
			testOpts: Options{
				IncludePrivate: true,
				GithubUser:     "fakeUser",
				GithubOrg:      "fakeOrg",
			},
			description:    "double owner",
			expectedErrMsg: "github user and organization set",
		},
		{
			testOpts: Options{
				IncludePrivate: true,
				GithubOrg:      "fakeOrg",
				OwnerPath:      "/dev/null",
			},
			description:    "local and remote target",
			expectedErrMsg: "github organization set and local owner path",
		},
		{
			testOpts: Options{
				IncludePrivate: true,
				GithubUser:     "fakeUser",
				OwnerPath:      "/dev/null",
			},
			description:    "local and remote target",
			expectedErrMsg: "github user set and local owner path",
		},
		{
			testOpts: Options{
				GithubUser:   "fakeUser",
				SingleSearch: "*/./....",
			},
			description:         "single search invalid regex gaurd",
			expectedErrMsgFuzzy: "unable to compile regex: */./...., ",
		},
		{
			testOpts: Options{
				GithubUser:   "fakeUser",
				SingleSearch: "mystring",
			},
			description:    "single search regex gaurd",
			expectedErrMsg: "",
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("Test Option Gaurd", func() {
			g.It(test.description, func() {
				os.Clearenv()
				opts = test.testOpts
				if test.githubToken {
					os.Setenv("GITHUB_TOKEN", "fakeToken")
				}
				err := optsGuard()
				if err != nil {
					if test.expectedErrMsgFuzzy != "" {
						g.Assert(strings.Contains(err.Error(), test.expectedErrMsgFuzzy)).Equal(true)
					} else {
						g.Assert(err.Error()).Equal(test.expectedErrMsg)
					}
				} else {
					g.Assert("").Equal(test.expectedErrMsg)
				}

			})
		})
	}
}

func TestLoadToml(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "gitleaksTestConfigDir")
	defer os.RemoveAll(tmpDir)
	err := ioutil.WriteFile(path.Join(tmpDir, "gitleaksConfig"), []byte(defaultConfig), 0644)
	if err != nil {
		panic(err)
	}

	configPath := path.Join(tmpDir, "gitleaksConfig")
	noConfigPath := path.Join(tmpDir, "gitleaksConfigNope")

	var tests = []struct {
		testOpts       Options
		description    string
		configPath     string
		expectedErrMsg string
		singleSearch   bool
	}{
		{
			testOpts: Options{
				ConfigPath: configPath,
			},
			description: "path to config",
		},
		{
			testOpts:     Options{},
			description:  "env var path to no config",
			singleSearch: true,
		},
		{
			testOpts: Options{
				ConfigPath: noConfigPath,
			},
			description:    "no path to config",
			expectedErrMsg: fmt.Sprintf("no gitleaks config at %s", noConfigPath),
		},
		{
			testOpts:       Options{},
			description:    "env var path to config",
			configPath:     configPath,
			expectedErrMsg: "",
		},
		{
			testOpts:       Options{},
			description:    "env var path to no config",
			configPath:     noConfigPath,
			expectedErrMsg: fmt.Sprintf("problem loading config: open %s: no such file or directory", noConfigPath),
		},
	}

	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestLoadToml", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				if test.singleSearch {
					singleSearchRegex = regexp.MustCompile("test")
				} else {
					singleSearchRegex = nil
				}
				if test.configPath != "" {
					os.Setenv("GITLEAKS_CONFIG", test.configPath)
				} else {
					os.Clearenv()
				}
				err := loadToml()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				} else {
					g.Assert("").Equal(test.expectedErrMsg)
				}
			})
		})
	}
}
