package main

import (
	"context"
	"github.com/google/go-github/github"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	regexes            map[string]*regexp.Regexp
	stopWords          []string
	base64Chars        string
	hexChars           string
	assignRegex        *regexp.Regexp
	fileDiffRegex      *regexp.Regexp
	gitLeaksPath       string
	gitLeaksClonePath  string
	gitLeaksReportPath string
)

type RepoDesc struct {
	name  string
	url   string
	path  string
	owner *Owner
}

type Owner struct {
	name        string
	url         string
	accountType string
	path        string
	reportPath  string
}

func init() {
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"

	stopWords = []string{"setting", "info", "env", "environment"}

	regexes = map[string]*regexp.Regexp{
		"PKCS8":    regexp.MustCompile("-----BEGIN PRIVATE KEY-----"),
		"RSA":      regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
                "DSA":      regexp.MustCompile("-----BEGIN DSA PRIVATE KEY-----"),
		"SSH":      regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		"Facebook": regexp.MustCompile("(?i)facebook.*['\"][0-9a-f]{32}['\"]"),
		"Twitter":  regexp.MustCompile("(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]"),
		"Github":   regexp.MustCompile("(?i)github.*['\"][0-9a-zA-Z]{35,40}['\"]"),
		"AWS":      regexp.MustCompile("AKIA[0-9A-Z]{16}"),
		"Reddit":   regexp.MustCompile("(?i)reddit.*['\"][0-9a-zA-Z]{14}['\"]"),
		"Heroku":   regexp.MustCompile("(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
		// "Custom": regexp.MustCompile(".*")
	}
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
	fileDiffRegex = regexp.MustCompile("diff --git a.+b/")
	homeDir, err := homedir.Dir()
	if err != nil {
		log.Fatal("Cant find home dir")
	}

	gitLeaksPath = filepath.Join(homeDir, ".gitleaks")
	if _, err := os.Stat(gitLeaksPath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksPath, os.ModePerm)
	}
	gitLeaksClonePath = filepath.Join(gitLeaksPath, "clones")
	if _, err := os.Stat(gitLeaksClonePath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksClonePath, os.ModePerm)
	}
	gitLeaksReportPath = filepath.Join(gitLeaksPath, "report")
	if _, err := os.Stat(gitLeaksReportPath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksReportPath, os.ModePerm)
	}
}

// getOwner
func getOwner(opts *Options) *Owner {
	var owner Owner
	if opts.RepoURL != "" {
		splitSlashes := strings.Split(opts.RepoURL, "/")
		owner = Owner{
			name:        splitSlashes[len(splitSlashes)-2],
			url:         opts.RepoURL,
			accountType: "users",
		}

	} else if opts.UserURL != "" {
		_, ownerName := path.Split(opts.UserURL)
		owner = Owner{
			name:        ownerName,
			url:         opts.UserURL,
			accountType: "user",
		}
	} else if opts.OrgURL != "" {
		_, ownerName := path.Split(opts.OrgURL)
		owner = Owner{
			name:        ownerName,
			url:         opts.OrgURL,
			accountType: "org",
		}
	}

	if opts.Tmp {
		dir, err := ioutil.TempDir("", owner.name)
		if err != nil {
			log.Fatal("Cant make temp dir")
		}
		owner.path = dir
	} else {
		owner.path = filepath.Join(gitLeaksClonePath, owner.name)
		if _, err := os.Stat(owner.path); os.IsNotExist(err) {
			os.Mkdir(owner.path, os.ModePerm)
		}
	}
	owner.reportPath = filepath.Join(gitLeaksPath, "report", owner.name)
	return &owner
}

// getRepos
func getRepos(opts *Options, owner *Owner) []RepoDesc {
	var (
		allRepos  []*github.Repository
		repos     []*github.Repository
		repoDescs []RepoDesc
		resp      *github.Response
		ctx       = context.Background()
		err       error
	)
	if opts.RepoURL != "" {
		_, repoName := path.Split(opts.RepoURL)
		if strings.HasSuffix(repoName, ".git") {
			repoName = repoName[:len(repoName)-4]
		}
		ownerPath := filepath.Join(owner.path, repoName)
		repo := RepoDesc{
			name:  repoName,
			url:   opts.RepoURL,
			owner: owner,
			path:  ownerPath}
		repoDescs = append(repoDescs, repo)
		return repoDescs
	}

	tokenClient := getAccessToken(opts)
	gitClient := github.NewClient(tokenClient)

	// TODO include fork check
	orgOpt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	}
	userOpt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	}

	for {
		if opts.UserURL != "" {
			repos, resp, err = gitClient.Repositories.List(
				ctx, owner.name, userOpt)
		} else if opts.OrgURL != "" {
			repos, resp, err = gitClient.Repositories.ListByOrg(
				ctx, owner.name, orgOpt)
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 || err != nil {
			break
		}

		for _, repo := range repos {
			repoPath := filepath.Join(owner.path, *repo.Name)
			repoDescs = append(repoDescs,
				RepoDesc{
					name:  *repo.Name,
					url:   *repo.CloneURL,
					owner: owner,
					path:  repoPath})
		}

		orgOpt.Page = resp.NextPage
		userOpt.Page = resp.NextPage
	}

	return repoDescs
}

// getAccessToken checks
// 1. option
// 2. env var
// TODO. $HOME/.gitleaks/.creds
func getAccessToken(opts *Options) *http.Client {
	var token string
	if opts.Token != "" {
		token = opts.Token
	} else {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return nil
	}

	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context.Background(), tokenService)
	return tokenClient
}

func main() {
	args := os.Args[1:]
	opts := parseOptions(args)
	owner := getOwner(opts)
	repos := getRepos(opts, owner)
	start(repos, owner, opts)
}
