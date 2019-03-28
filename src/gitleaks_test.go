package gitleaks

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

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

const testWhitelistRegex = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
regexes= [
  "AKIA",
]
`

const testWhitelistRepo = `
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''

[whitelist]
repos = [
  "gronit",
]
`

const testEntropyRange = `
[misc]
entropy = [
  "7.5-8.0",
  "3.3-3.4",
]
`
const testBadEntropyRange = `
[misc]
entropy = [
  "8.0-3.0",
]
`
const testBadEntropyRange2 = `
[misc]
entropy = [
  "8.0-8.9",
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
				Repo: "https://github.com/gitleakstest/private",
			},
			description:    "test private repo",
			expectedErrMsg: "invalid auth method",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/private",
				Disk: true,
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
				_, err := cloneRepo()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				}
			})
		})
	}
}
func TestRun(t *testing.T) {
	var err error
	configsDir := testTomlLoader()

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
		whiteListRepos []string
		whiteListFiles []*regexp.Regexp
		numLeaks       int
		configPath     string
		commitPerPage  int
	}{
		{
			testOpts: Options{
				GitLabUser: "gitleakstest",
			},
			description:    "test github user",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubUser: "gitleakstest",
			},
			description:    "test github user",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubUser: "gitleakstest",
				Disk:       true,
			},
			description:    "test github user on disk ",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg: "gitleakstestorg",
			},
			description:    "test github org",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg: "gitleakstestorg",
				Disk:      true,
			},
			description:    "test org on disk",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				OwnerPath: dir,
			},
			description:    "test owner path",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo:   "git@github.com:gitleakstest/gronit.git",
				SSHKey: "trash",
			},
			description:    "test leak",
			numLeaks:       0,
			expectedErrMsg: "unable to generate ssh key: open trash: no such file or directory",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/gronit.git",
			},
			description:    "test leak",
			numLeaks:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/h1domains.git",
			},
			description:    "test clean",
			numLeaks:       0,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo: "https://github.com/gitleakstest/empty.git",
			},
			description:    "test empty",
			numLeaks:       0,
			expectedErrMsg: "reference not found",
		},
		{
			testOpts: Options{
				GithubOrg: "gitleakstestorg",
			},
			description:    "test github org, whitelist repo",
			numLeaks:       0,
			expectedErrMsg: "",
			configPath:     path.Join(configsDir, "repo"),
		},
		{
			testOpts: Options{
				GithubOrg:    "gitleakstestorg",
				ExcludeForks: true,
			},
			description:    "test github org, exclude forks",
			numLeaks:       0,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubPR: "https://github.com/gitleakstest/gronit/pull/1",
			},
			description:    "test github pr",
			numLeaks:       4,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubPR: "https://github.com/gitleakstest/gronit/pull/1",
			},
			description:    "test github pr",
			numLeaks:       4,
			expectedErrMsg: "",
			commitPerPage:  1,
		},
		{
			testOpts: Options{
				GithubPR: "https://github.com/gitleakstest/gronit/pull/1",
			},
			description:    "test github pr with whitelisted files",
			numLeaks:       0,
			expectedErrMsg: "",
			commitPerPage:  1,
			whiteListFiles: []*regexp.Regexp{
				regexp.MustCompile("main.go"),
			},
		},
		{
			testOpts: Options{
				GithubPR: "https://github.com/gitleakstest/gronit/pull/2",
			},
			description:    "test github pr with commits without patch info",
			numLeaks:       0,
			expectedErrMsg: "",
			commitPerPage:  1,
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestRun", func() {
			g.It(test.description, func() {
				if test.configPath != "" {
					os.Setenv("GITLEAKS_CONFIG", test.configPath)
				}
				if test.commitPerPage != 0 {
					githubPages = test.commitPerPage
				}
				if test.whiteListFiles != nil {
					whiteListFiles = test.whiteListFiles
				} else {
					whiteListFiles = nil
				}
				opts = test.testOpts
				leaks, err := run()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				}
				g.Assert(len(leaks)).Equal(test.numLeaks)
				githubPages = 100
			})
		})
	}
}

func TestWriteReport(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "reportDir")
	reportJSON := path.Join(tmpDir, "report.json")
	reportJASON := path.Join(tmpDir, "report.jason")
	reportVOID := path.Join("thereIsNoWay", "thisReportWillGetWritten.json")
	reportCSV := path.Join(tmpDir, "report.csv")
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
			Date:     time.Now(),
		},
	}

	var tests = []struct {
		leaks          []Leak
		reportFile     string
		fileName       string
		description    string
		testOpts       Options
		expectedErrMsg string
	}{
		{
			leaks:       leaks,
			reportFile:  reportJSON,
			fileName:    "report.json",
			description: "can we write a json file",
			testOpts: Options{
				Report: reportJSON,
			},
		},
		{
			leaks:       leaks,
			reportFile:  reportCSV,
			fileName:    "report.csv",
			description: "can we write a csv file",
			testOpts: Options{
				Report: reportCSV,
			},
		},
		{
			leaks:          leaks,
			reportFile:     reportJASON,
			fileName:       "report.jason",
			description:    "bad file",
			expectedErrMsg: "Report should be a .json or .csv file",
			testOpts: Options{
				Report: reportJASON,
			},
		},
		{
			leaks:          leaks,
			reportFile:     reportVOID,
			fileName:       "report.jason",
			description:    "bad dir",
			expectedErrMsg: "thereIsNoWay does not exist",
			testOpts: Options{
				Report: reportVOID,
			},
		},
	}
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestWriteReport", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				err := optsGuard()
				if err != nil {
					g.Assert(err.Error()).Equal(test.expectedErrMsg)
				} else {
					writeReport(test.leaks)
					f, _ := os.Stat(test.reportFile)
					g.Assert(f.Name()).Equal(test.fileName)
				}
			})
		})
	}

}

func testTomlLoader() string {
	tmpDir, _ := ioutil.TempDir("", "whiteListConfigs")
	ioutil.WriteFile(path.Join(tmpDir, "regex"), []byte(testWhitelistRegex), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "commit"), []byte(testWhitelistCommit), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "file"), []byte(testWhitelistFile), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "repo"), []byte(testWhitelistRepo), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "entropy"), []byte(testEntropyRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "badEntropy"), []byte(testBadEntropyRange), 0644)
	ioutil.WriteFile(path.Join(tmpDir, "badEntropy2"), []byte(testBadEntropyRange2), 0644)
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
	leaksR, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/gronit.git",
	})
	if err != nil {
		panic(err)
	}
	leaksRepo := &RepoDescriptor{
		repository: leaksR,
		name:       "gronit",
	}

	cleanR, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL: "https://github.com/gitleakstest/h1domains.git",
	})
	if err != nil {
		panic(err)
	}
	cleanRepo := &RepoDescriptor{
		repository: cleanR,
		name:       "h1domains",
	}

	var tests = []struct {
		testOpts         Options
		description      string
		expectedErrMsg   string
		numLeaks         int
		repo             *RepoDescriptor
		whiteListFiles   []*regexp.Regexp
		whiteListCommits map[string]bool
		whiteListRepos   []*regexp.Regexp
		whiteListRegexes []*regexp.Regexp
		configPath       string
	}{
		{
			repo:        leaksRepo,
			description: "pinned config",
			numLeaks:    0,
			testOpts: Options{
				RepoConfig: true,
			},
		},
		{
			repo:        leaksRepo,
			description: "commit depth = 1, one leak",
			numLeaks:    1,
			testOpts: Options{
				Depth: 1,
			},
		},
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
				Threads: 4,
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
			description: "Audit a specific commit",
			numLeaks:    1,
			testOpts: Options{
				Commit: "cb5599aeed261b2c038aa4729e2d53ca050a4988",
			},
		},
		{
			repo:        leaksRepo,
			description: "Audit a specific commit no leaks",
			numLeaks:    0,
			testOpts: Options{
				Commit: "2b033e012eee364fc41b4ab7c5db1497399b8e67",
			},
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist regex",
			configPath:  path.Join(configsDir, "regex"),
			numLeaks:    0,
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
		{
			repo:        leaksRepo,
			description: "audit whitelist repo",
			numLeaks:    0,
			whiteListRepos: []*regexp.Regexp{
				regexp.MustCompile("gronit"),
			},
		},
		{
			repo:        leaksRepo,
			description: "toml whitelist repo",
			numLeaks:    0,
			configPath:  path.Join(configsDir, "repo"),
		},
		{
			repo:        leaksRepo,
			description: "leaks present with entropy",
			testOpts: Options{
				Entropy: 4.7,
			},
			numLeaks: 6,
		},
		{
			repo:        leaksRepo,
			description: "leaks present with entropy",
			testOpts: Options{
				Entropy:        4.7,
				NoiseReduction: true,
			},
			numLeaks: 2,
		},
		{
			repo:        leaksRepo,
			description: "Audit until specific commit",
			numLeaks:    2,
			testOpts: Options{
				CommitStop: "f6839959b7bbdcd23008f1fb16f797f35bcd3a0c",
			},
		},
		{
			repo:        leaksRepo,
			description: "commit depth = 2, two leaks",
			numLeaks:    2,
			testOpts: Options{
				Depth: 2,
			},
		},
		{
			repo:        leaksRepo,
			description: "toml entropy range",
			numLeaks:    298,
			configPath:  path.Join(configsDir, "entropy"),
		},
		{
			repo: leaksRepo,
			testOpts: Options{
				NoiseReduction: true,
			},
			description: "toml entropy range",
			numLeaks:    58,
			configPath:  path.Join(configsDir, "entropy"),
		},
		{
			repo:           leaksRepo,
			description:    "toml bad entropy range",
			numLeaks:       0,
			configPath:     path.Join(configsDir, "badEntropy"),
			expectedErrMsg: "entropy range must be ascending",
		},
		{
			repo:           leaksRepo,
			description:    "toml bad entropy2 range",
			numLeaks:       0,
			configPath:     path.Join(configsDir, "badEntropy2"),
			expectedErrMsg: "invalid entropy ranges, must be within 0.0-8.0",
		},
	}
	whiteListCommits = make(map[string]bool)
	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestAuditRepo", func() {
			g.It(test.description, func() {
				auditDone = false
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
				if test.whiteListRegexes != nil {
					whiteListRegexes = test.whiteListRegexes
				} else {
					whiteListRegexes = nil
				}
				if test.whiteListRepos != nil {
					whiteListRepos = test.whiteListRepos
				} else {
					whiteListRepos = nil
				}
				skip := false
				totalCommits = 0
				// config paths
				if test.configPath != "" {
					os.Setenv("GITLEAKS_CONFIG", test.configPath)
					err := loadToml()
					if err != nil {
						g.Assert(err.Error()).Equal(test.expectedErrMsg)
						skip = true
					}
				}
				if !skip {
					leaks, err = auditGitRepo(test.repo)
					if test.testOpts.Depth != 0 {
						g.Assert(totalCommits).Equal(test.testOpts.Depth)
					} else {
						if opts.Redact {
							g.Assert(leaks[0].Offender).Equal("REDACTED")
						}
						g.Assert(len(leaks)).Equal(test.numLeaks)
					}
				}
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
				GithubUser: "fakeUser",
				GithubOrg:  "fakeOrg",
			},
			description:    "double owner",
			expectedErrMsg: "github user and organization set",
		},
		{
			testOpts: Options{
				GithubOrg: "fakeOrg",
				OwnerPath: "/dev/null",
			},
			description:    "local and remote target",
			expectedErrMsg: "github organization set and local owner path",
		},
		{
			testOpts: Options{
				GithubUser: "fakeUser",
				OwnerPath:  "/dev/null",
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
		{
			testOpts: Options{
				GithubOrg: "fakeOrg",
				Entropy:   9,
			},
			description:    "Invalid entropy level guard",
			expectedErrMsg: "The maximum level of entropy is 8",
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
