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

func TestGetRepo(t *testing.T) {
	var err error
	dir, err = ioutil.TempDir("", "gitleaksTestRepo")
	defer os.RemoveAll(dir)
	if err != nil {
		panic(err)
	}
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL: "https://github.com/zricethezav/gronit",
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
				Repo: "https://github.com/zricethezav/gronit",
			},
			description:    "test plain clone remote repo",
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				Repo:  "https://github.com/zricethezav/gronit",
				InMem: true,
			},
			description:    "test inmem clone remote repo",
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
				Repo: "https://github.com/zricethezav/nope",
			},
			description:    "test no repo",
			expectedErrMsg: "authentication required",
		},
		{
			testOpts: Options{
				Repo:           "https://github.com/zricethezav/private",
				IncludePrivate: true,
			},
			description:    "test private repo",
			expectedErrMsg: "invalid auth method",
		},
		{
			testOpts: Options{
				Repo:           "https://github.com/zricethezav/private",
				IncludePrivate: true,
				InMem:          true,
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
		URL: "https://github.com/zricethezav/gronit",
	})
	git.PlainClone(dir+"/h1domains", false, &git.CloneOptions{
		URL: "https://github.com/zricethezav/h1domains",
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
				InMem:      true,
			},
			description:    "test github user in mem",
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
				InMem:     true,
			},
			description:    "test org in mem",
			numRepos:       2,
			expectedErrMsg: "",
		},
		{
			testOpts: Options{
				GithubOrg:      "gitleakstestorg",
				IncludePrivate: true,
				InMem:          true,
			},
			description:    "test private org in mem no ssh",
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

func TestAuditRepo(t *testing.T) {
	var leaks []Leak
	err := loadToml()
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
		testOpts       Options
		description    string
		expectedErrMsg string
		numLeaks       int
		repo           *git.Repository
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
			repo:        cleanRepo,
			description: "no leaks present",
			numLeaks:    0,
		},
	}

	g := goblin.Goblin(t)
	for _, test := range tests {
		g.Describe("TestAuditRepo", func() {
			g.It(test.description, func() {
				opts = test.testOpts
				leaks, err = auditRepo(test.repo)
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
