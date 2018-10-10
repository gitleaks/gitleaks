package main

import (
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/src-d/go-git.v4/plumbing"

	"golang.org/x/oauth2"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
	"gopkg.in/src-d/go-git.v4/storage/memory"

	"github.com/BurntSushi/toml"
	"github.com/google/go-github/github"
	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
)

// Leak represents a leaked secret or regex match.
// Output to stdout as json if the --verbose option is set or
// as a csv if the --csv and --report options are set.
type Leak struct {
	Line     string `json:"line"`
	Commit   string `json:"commit"`
	Offender string `json:"offender"`
	Type     string `json:"reason"`
	Message  string `json:"commitMsg"`
	Author   string `json:"author"`
	File     string `json:"file"`
	Branch   string `json:"branch"`
	Repo     string `json:"repo"`
}

// RepoDescriptor contains a src-d git repository and other data about the repo
type RepoDescriptor struct {
	path       string
	url        string
	name       string
	repository *git.Repository
	err        error
}

// Options for gitleaks
type Options struct {
	// remote target options
	Repo           string `short:"r" long:"repo" description:"Repo url to audit"`
	GithubUser     string `long:"github-user" description:"Github user to audit"`
	GithubOrg      string `long:"github-org" description:"Github organization to audit"`
	GithubURL      string `long:"github-url" default:"https://api.github.com/" description:"GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/"`
	IncludePrivate bool   `short:"p" long:"private" description:"Include private repos in audit"`

	/*
		TODO:
		GitLabUser string `long:"gitlab-user" description:"User url to audit"`
		GitLabOrg  string `long:"gitlab-org" description:"Organization url to audit"`
	*/

	Branch string `short:"b" long:"branch" description:"branch name to audit (defaults to HEAD)"`
	Commit string `short:"c" long:"commit" description:"sha of commit to stop at"`
	Depth  int    `long:"depth" description:"maximum commit depth"`

	// local target option
	RepoPath  string `long:"repo-path" description:"Path to repo"`
	OwnerPath string `long:"owner-path" description:"Path to owner directory (repos discovered)"`

	// Process options
	MaxGoRoutines int     `long:"max-go" description:"Maximum number of concurrent go-routines gitleaks spawns"`
	Disk          bool    `long:"disk" description:"Clones repo(s) to disk"`
	AuditAllRefs  bool    `long:"all-refs" description:"run audit on all refs"`
	SingleSearch  string  `long:"single-search" description:"single regular expression to search for"`
	ConfigPath    string  `long:"config" description:"path to gitleaks config"`
	SSHKey        string  `long:"ssh-key" description:"path to ssh key"`
	ExcludeForks  bool    `long:"exclude-forks" description:"exclude forks for organization/user audits"`
	Entropy       float64 `long:"entropy" short:"e" description:"Include entropy checks during audit. Entropy scale: 0.0(no entropy) - 8.0(max entropy)"`
	// TODO: IncludeMessages  string `long:"messages" description:"include commit messages in audit"`

	// Output options
	Log          string `short:"l" long:"log" description:"log level"`
	Verbose      bool   `short:"v" long:"verbose" description:"Show verbose output from gitleaks audit"`
	Report       string `long:"report" description:"path to write report file"`
	CSV          bool   `long:"csv" description:"report output to csv"`
	Redact       bool   `long:"redact" description:"redact secrets from log messages and report"`
	Version      bool   `long:"version" description:"version number"`
	SampleConfig bool   `long:"sample-config" description:"prints a sample config file"`
}

// Config struct for regexes matching and whitelisting
type Config struct {
	Regexes []struct {
		Description string
		Regex       string
	}
	Whitelist struct {
		Files    []string
		Regexes  []string
		Commits  []string
		Branches []string
		Repos    []string
	}
}

type gitDiff struct {
	content    string
	commit     *object.Commit
	filePath   string
	branchName string
	repoName   string
}

const defaultGithubURL = "https://api.github.com/"
const version = "1.11.0"
const errExit = 2
const leakExit = 1
const defaultConfig = `
# This is a sample config file for gitleaks. You can configure gitleaks what to search for and what to whitelist.
# The output you are seeing here is the default gitleaks config. If GITLEAKS_CONFIG environment variable
# is set, gitleaks will load configurations from that path. If option --config-path is set, gitleaks will load
# configurations from that path. Gitleaks does not whitelist anything by default.


title = "gitleaks config"
# add regexes to the regex table
[[regexes]]
description = "AWS"
regex = '''AKIA[0-9A-Z]{16}'''
[[regexes]]
description = "RKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
[[regexes]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
[[regexes]]
description = "Github"
regex = '''(?i)github.*['\"][0-9a-zA-Z]{35,40}['\"]'''
[[regexes]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
[[regexes]]
description = "Facebook"
regex = '''(?i)facebook.*['\"][0-9a-f]{32}['\"]'''
[[regexes]]
description = "Twitter"
regex = '''(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]'''

[whitelist]
#regexes = [
#  "AKAIMYFAKEAWKKEY",
#]

#files = [
#  "(.*?)(jpg|gif|doc|pdf|bin)$"
#]

#commits = [
#  "BADHA5H1",
#  "BADHA5H2",
#]

#branches = [
#	"dev/STUPDIFKNFEATURE"
#]

#repos = [
#	"someYugeRepoWeKnowIsCLEAR"
#]
`

var (
	opts              Options
	regexes           map[string]*regexp.Regexp
	singleSearchRegex *regexp.Regexp
	whiteListRegexes  []*regexp.Regexp
	whiteListFiles    []*regexp.Regexp
	whiteListCommits  map[string]bool
	whiteListBranches []string
	whiteListRepos    []string
	fileDiffRegex     *regexp.Regexp
	sshAuth           *ssh.PublicKeys
	dir               string
	maxGo             int
	totalCommits      int64
)

func init() {
	log.SetOutput(os.Stdout)
	maxGo = runtime.GOMAXPROCS(0) / 2
	regexes = make(map[string]*regexp.Regexp)
	whiteListCommits = make(map[string]bool)
}

func main() {
	_, err := flags.Parse(&opts)
	if opts.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	if opts.SampleConfig {
		fmt.Println(defaultConfig)
		os.Exit(0)
	}
	leaks, err := run()
	if err != nil {
		log.Error(err)
		os.Exit(errExit)
	}
	if opts.Report != "" {
		writeReport(leaks)
	}

	log.Infof("%d commits inspected, %d leaks detected", totalCommits, len(leaks))
	if len(leaks) != 0 {
		log.Warnf("leaks detected")
		os.Exit(leakExit)
	}
}

// run parses options and kicks off the audit
func run() ([]Leak, error) {
	var leaks []Leak
	setLogs()
	err := optsGuard()
	if err != nil {
		return nil, err
	}
	err = loadToml()
	if err != nil {
		return nil, err
	}
	if opts.IncludePrivate {
		// if including private repos use ssh as authentication
		sshAuth, err = getSSHAuth()
		if err != nil {
			return nil, err
		}
	}
	if opts.Disk {
		// temporary directory where all the gitleaks plain clones will reside
		dir, err = ioutil.TempDir("", "gitleaks")
		defer os.RemoveAll(dir)
		if err != nil {
			return nil, err
		}
	}

	// start audits
	if opts.Repo != "" || opts.RepoPath != "" {
		// Audit a single remote repo or a local repo.
		repo, err := cloneRepo()
		if err != nil {
			return leaks, err
		}
		return auditGitRepo(repo)
	} else if opts.OwnerPath != "" {
		// Audit local repos. Gitleaks will look for all child directories of OwnerPath for
		// git repos and perform an audit on said repos.
		repos, err := discoverRepos(opts.OwnerPath)
		if err != nil {
			return leaks, err
		}
		for _, repo := range repos {
			leaksFromRepo, err := auditGitRepo(repo)
			if err != nil {
				return leaks, err
			}
			leaks = append(leaksFromRepo, leaks...)
		}
	} else if opts.GithubOrg != "" || opts.GithubUser != "" {
		// Audit a github owner -- a user or organization. If you want to include
		// private repos you must pass a --private/-p option and have your ssh keys set
		leaks, err = auditGithubRepos()
		if err != nil {
			return leaks, err
		}
	}
	return leaks, nil
}

// writeReport writes a report to a file specified in the --report= option.
// Default format for report is JSON. You can use the --csv option to write the report as a csv
func writeReport(leaks []Leak) error {
	var err error
	log.Infof("writing report to %s", opts.Report)
	if opts.CSV {
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"repo", "line", "commit", "offender", "reason", "commitMsg", "author", "file", "branch"})
		for _, leak := range leaks {
			w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Type, leak.Message, leak.Author, leak.File, leak.Branch})
		}
		w.Flush()
	} else {
		reportJSON, _ := json.MarshalIndent(leaks, "", "\t")
		err = ioutil.WriteFile(opts.Report, reportJSON, 0644)
	}
	return err
}

// cloneRepo clones a repo to memory(default) or to disk if the --disk option is set. If you want to
// clone a private repo you must set the --private/-p option, use a ssh target, and have your ssh keys
// configured. If you want to audit a local repo, getRepo will load up a repo located at --repo-path
func cloneRepo() (*RepoDescriptor, error) {
	var (
		err  error
		repo *git.Repository
	)
	if opts.Disk {
		log.Infof("cloning %s", opts.Repo)
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if opts.IncludePrivate {
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     sshAuth,
			})
		} else {
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	} else if opts.RepoPath != "" {
		log.Infof("opening %s", opts.Repo)
		repo, err = git.PlainOpen(opts.RepoPath)
	} else {
		log.Infof("cloning %s", opts.Repo)
		if opts.IncludePrivate {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     sshAuth,
			})
		} else {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	}
	return &RepoDescriptor{
		repository: repo,
		path:       opts.RepoPath,
		url:        opts.Repo,
		name:       filepath.Base(opts.Repo),
		err:        err,
	}, nil
}

// auditGitRepo beings an audit on a git repository by checking the default HEAD branch, all branches, or
// a single branch depending on what gitleaks is configured to do. Note when I say branch I really
// mean reference as these branches are read only.
func auditGitRepo(repo *RepoDescriptor) ([]Leak, error) {
	var (
		err   error
		leaks []Leak
	)
	for _, repoName := range whiteListRepos {
		if repoName == repo.name {
			return nil, fmt.Errorf("skipping %s, whitelisted", repoName)
		}
	}
	ref, err := repo.repository.Head()
	if err != nil {
		return leaks, err
	}

	if opts.AuditAllRefs {
		skipBranch := false
		refs, err := repo.repository.Storer.IterReferences()
		if err != nil {
			return leaks, err
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			for _, b := range whiteListBranches {
				if strings.HasSuffix(string(ref.Name()), b) {
					skipBranch = true
				}
			}
			if skipBranch {
				skipBranch = false
				return nil
			}
			branchLeaks := auditGitReference(repo, ref)
			for _, leak := range branchLeaks {
				leaks = append(leaks, leak)
			}
			return nil
		})
	} else {
		if opts.Branch != "" {
			foundBranch := false
			refs, _ := repo.repository.Storer.IterReferences()
			branch := strings.Split(opts.Branch, "/")[len(strings.Split(opts.Branch, "/"))-1]
			err = refs.ForEach(func(refBranch *plumbing.Reference) error {
				if strings.Split(refBranch.Name().String(), "/")[len(strings.Split(refBranch.Name().String(), "/"))-1] == branch {
					foundBranch = true
					ref = refBranch
				}
				return nil
			})
			if foundBranch == false {
				return nil, nil
			}
		}
		leaks = auditGitReference(repo, ref)
	}
	return leaks, err
}

// auditGitReference beings the audit for a git reference. This function will
// traverse the git reference and audit each line of each diff. Set maximum concurrency with
// the --max-go option (default is set to the number of cores on your cpu).
func auditGitReference(repo *RepoDescriptor, ref *plumbing.Reference) []Leak {
	var (
		err         error
		prevCommit  *object.Commit
		semaphore   chan bool
		repoName    string
		leaks       []Leak
		commitWg    sync.WaitGroup
		mutex       = &sync.Mutex{}
		commitCount int
	)
	repoName = repo.name
	if opts.MaxGoRoutines != 0 {
		maxGo = opts.MaxGoRoutines
	}

	semaphore = make(chan bool, maxGo)
	cIter, err := repo.repository.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil
	}
	err = cIter.ForEach(func(c *object.Commit) error {
		if c.Hash.String() == opts.Commit || (opts.Depth != 0 && commitCount == opts.Depth) {
			cIter.Close()
			return errors.New("ErrStop")
		}
		commitCount = commitCount + 1
		totalCommits = totalCommits + 1
		if whiteListCommits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}
		commitWg.Add(1)
		semaphore <- true
		go func(c *object.Commit, prevCommit *object.Commit) {
			var (
				filePath string
				skipFile bool
			)
			defer func() {
				commitWg.Done()
				<-semaphore
				if r := recover(); r != nil {
					log.Warnf("recoverying from panic on commit %s, likely large diff causing panic", c.Hash.String())
				}
			}()
			diff := gitDiff{
				commit:     prevCommit,
				branchName: string(ref.Name()),
				repoName:   repoName,
			}

			if prevCommit == nil {
				t, _ := c.Tree()
				files := t.Files()
				err := files.ForEach(func(file *object.File) error {
					content, err := file.Contents()
					if err != nil {
						return err
					}
					diff.filePath = file.Name
					diff.content = content
					diff.commit = c
					chunkLeaks := inspect(diff)
					for _, leak := range chunkLeaks {
						mutex.Lock()
						leaks = append(leaks, leak)
						mutex.Unlock()
					}
					return nil
				})
				if err != nil {
					log.Warnf("problem generating diff for commit: %s\n", c.Hash.String())
					return
				}
			} else {
				patch, err := c.Patch(prevCommit)
				if err != nil {
					log.Warnf("problem generating patch for commit: %s\n", c.Hash.String())
					return
				}
				for _, f := range patch.FilePatches() {
					skipFile = false
					from, to := f.Files()
					filePath = "???"
					if from != nil {
						filePath = from.Path()
					} else if to != nil {
						filePath = to.Path()
					}
					diff.filePath = filePath
					for _, re := range whiteListFiles {
						if re.FindString(filePath) != "" {
							skipFile = true
							break
						}
					}
					if skipFile {
						continue
					}
					chunks := f.Chunks()
					for _, chunk := range chunks {
						if chunk.Type() == 1 || chunk.Type() == 2 {
							diff.content = chunk.Content()
							chunkLeaks := inspect(diff)
							for _, leak := range chunkLeaks {
								mutex.Lock()
								leaks = append(leaks, leak)
								mutex.Unlock()
							}
						}
					}
				}
			}
		}(c, prevCommit)
		prevCommit = c
		return nil
	})
	commitWg.Wait()

	if opts.Verbose {
		log.Infof("%d commits inspected for %s", commitCount, repo.name)
	}

	return leaks
}

// inspect will parse each line of the git diff's content against a set of regexes or
// a set of regexes set by the config (see gitleaks.toml for example). This function
// will skip lines that include a whitelisted regex. A list of leaks is returned.
// If verbose mode (-v/--verbose) is set, then checkDiff will log leaks as they are discovered.
func inspect(diff gitDiff) []Leak {
	lines := strings.Split(diff.content, "\n")
	var (
		leaks    []Leak
		skipLine bool
	)

	for _, line := range lines {
		skipLine = false
		for leakType, re := range regexes {
			match := re.FindString(line)
			if match == "" {
				continue
			}

			// if offender matches whitelist regex, ignore it
			for _, wRe := range whiteListRegexes {
				whitelistMatch := wRe.FindString(line)
				if whitelistMatch != "" {
					skipLine = true
					break
				}
			}
			if skipLine {
				break
			}

			leaks = addLeak(leaks, line, match, leakType, diff)
		}

		if opts.Entropy > 0 {
			words := strings.Fields(line)
			for _, word := range words {
				if getShannonEntropy(word) >= opts.Entropy {
					leaks = addLeak(leaks, line, word, "High Entropy", diff)
				}
			}
		}
	}
	return leaks
}

// getShannonEntropy https://en.wiktionary.org/wiki/Shannon_entropy
func getShannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// addLeak is helper for func inspect() to append leaks if found during a diff check.
func addLeak(leaks []Leak, line string, offender string, leakType string, diff gitDiff) []Leak {
	leak := Leak{
		Line:     line,
		Commit:   diff.commit.Hash.String(),
		Offender: offender,
		Type:     leakType,
		Message:  diff.commit.Message,
		Author:   diff.commit.Author.String(),
		File:     diff.filePath,
		Branch:   diff.branchName,
		Repo:     diff.repoName,
	}

	if opts.Redact {
		leak.Offender = "REDACTED"
		leak.Line = "REDACTED"
	}

	if opts.Verbose {
		leak.log()
	}

	leaks = append(leaks, leak)
	return leaks
}

// auditGithubRepos kicks off audits if --github-user or --github-org options are set.
// First, we gather all the github repositories from the github api (this doesnt actually clone the repo).
// After all the repos have been pulled from github's api we proceed to audit the repos by calling auditGithubRepo.
// If an error occurs during an audit of a repo, that error is logged but won't break the execution cycle.
func auditGithubRepos() ([]Leak, error) {
	var (
		err              error
		githubRepos      []*github.Repository
		pagedGithubRepos []*github.Repository
		resp             *github.Response
		githubClient     *github.Client
		githubOrgOptions *github.RepositoryListByOrgOptions
		githubOptions    *github.RepositoryListOptions
		done             bool
		leaks            []Leak
		ownerDir         string
	)
	ctx := context.Background()

	if opts.GithubOrg != "" {
		githubClient = github.NewClient(githubToken())
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}
		githubOrgOptions = &github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		}
	} else if opts.GithubUser != "" {
		githubClient = github.NewClient(githubToken())
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}

		githubOptions = &github.RepositoryListOptions{
			Affiliation: "owner",
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		}
	}

	for {
		if done {
			break
		}
		if opts.GithubUser != "" {
			if opts.IncludePrivate {
				pagedGithubRepos, resp, err = githubClient.Repositories.List(ctx, "", githubOptions)
			} else {
				pagedGithubRepos, resp, err = githubClient.Repositories.List(ctx, opts.GithubUser, githubOptions)
			}
			if err != nil {
				done = true
			}
			githubOptions.Page = resp.NextPage
			githubRepos = append(githubRepos, pagedGithubRepos...)
			if resp.NextPage == 0 {
				done = true
			}
		} else if opts.GithubOrg != "" {
			pagedGithubRepos, resp, err = githubClient.Repositories.ListByOrg(ctx, opts.GithubOrg, githubOrgOptions)
			if err != nil {
				done = true
			}
			githubOrgOptions.Page = resp.NextPage
			githubRepos = append(githubRepos, pagedGithubRepos...)
			if resp.NextPage == 0 {
				done = true
			}
		}
		if opts.Log == "Debug" || opts.Log == "debug" {
			for _, githubRepo := range pagedGithubRepos {
				log.Debugf("staging repos %s", *githubRepo.Name)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if opts.Disk {
		ownerDir, err = ioutil.TempDir(dir, opts.GithubUser)
		os.RemoveAll(ownerDir)
	}
	for _, githubRepo := range githubRepos {
		repo, err := cloneGithubRepo(githubRepo)
		if err != nil {
			log.Warn(err)
			continue
		}
		leaksFromRepo, err := auditGitRepo(repo)
		if opts.Disk {
			os.RemoveAll(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name))
		}
		if len(leaksFromRepo) == 0 {
			log.Infof("no leaks found for repo %s", *githubRepo.Name)
		} else {
			log.Warnf("leaks found for repo %s", *githubRepo.Name)
		}
		if err != nil {
			log.Warn(err)
		}
		leaks = append(leaks, leaksFromRepo...)
	}
	return leaks, nil
}

// cloneGithubRepo clones a repo from the url parsed from a github repo. The repo
// will be cloned to disk if --disk is set. If the repo is private, you must include the
// --private/-p option. After the repo is clone, an audit will begin.
func cloneGithubRepo(githubRepo *github.Repository) (*RepoDescriptor, error) {
	var (
		repo *git.Repository
		err  error
	)
	if opts.ExcludeForks && githubRepo.GetFork() {
		return nil, fmt.Errorf("skipping %s, excluding forks", *githubRepo.Name)
	}
	for _, repoName := range whiteListRepos {
		if repoName == *githubRepo.Name {
			return nil, fmt.Errorf("skipping %s, whitelisted", repoName)
		}
	}
	log.Infof("cloning: %s", *githubRepo.Name)
	if opts.Disk {
		ownerDir, err := ioutil.TempDir(dir, opts.GithubUser)
		if err != nil {
			return nil, fmt.Errorf("unable to generater owner temp dir: %v", err)
		}
		if opts.IncludePrivate {
			if sshAuth == nil {
				return nil, fmt.Errorf("no ssh auth available")
			}
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name), false, &git.CloneOptions{
				URL:  *githubRepo.SSHURL,
				Auth: sshAuth,
			})
		} else {
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name), false, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
			})
		}
	} else {
		if opts.IncludePrivate {
			if sshAuth == nil {
				return nil, fmt.Errorf("no ssh auth available")
			}
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:  *githubRepo.SSHURL,
				Auth: sshAuth,
			})
		} else {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
			})
		}
	}
	if err != nil {
		return nil, err
	}
	return &RepoDescriptor{
		repository: repo,
		name:       *githubRepo.Name,
	}, nil
}

// githubToken returns an oauth2 client for the github api to consume. This token is necessary
// if you are running audits with --github-user or --github-org
func githubToken() *http.Client {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		return nil
	}
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	return oauth2.NewClient(context.Background(), ts)
}

// discoverRepos walks all the children of `path`. If a child directory
// contain a .git file then that repo will be added to the list of repos returned
func discoverRepos(ownerPath string) ([]*RepoDescriptor, error) {
	var (
		err   error
		repos []*RepoDescriptor
	)
	files, err := ioutil.ReadDir(ownerPath)
	if err != nil {
		return repos, err
	}
	for _, f := range files {
		if f.IsDir() {
			repoPath := path.Join(ownerPath, f.Name())
			r, err := git.PlainOpen(repoPath)
			if err != nil {
				continue
			}
			repos = append(repos, &RepoDescriptor{
				repository: r,
				name:       f.Name(),
				path:       repoPath,
			})
		}
	}
	return repos, err
}

// setLogLevel sets log level for gitleaks. Default is Warning
func setLogs() {
	switch opts.Log {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}

// optsGuard prevents invalid options
func optsGuard() error {
	var err error
	if opts.GithubOrg != "" && opts.GithubUser != "" {
		return fmt.Errorf("github user and organization set")
	} else if opts.GithubOrg != "" && opts.OwnerPath != "" {
		return fmt.Errorf("github organization set and local owner path")
	} else if opts.GithubUser != "" && opts.OwnerPath != "" {
		return fmt.Errorf("github user set and local owner path")
	} else if opts.IncludePrivate && os.Getenv("GITHUB_TOKEN") == "" && (opts.GithubOrg != "" || opts.GithubUser != "") {
		return fmt.Errorf("user/organization private repos require env var GITHUB_TOKEN to be set")
	}

	// do the URL Parse and error checking here, so we can skip it later
	// empty string is OK, it will default to the public github URL.
	if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
		if !strings.HasSuffix(opts.GithubURL, "/") {
			opts.GithubURL += "/"
		}
		ghURL, err := url.Parse(opts.GithubURL)
		if err != nil {
			return err
		}
		tcpPort := "443"
		if ghURL.Scheme == "http" {
			tcpPort = "80"
		}
		timeout := time.Duration(1 * time.Second)
		_, err = net.DialTimeout("tcp", ghURL.Host+":"+tcpPort, timeout)
		if err != nil {
			return fmt.Errorf("%s unreachable, error: %s", ghURL.Host, err)
		}
	}

	if opts.SingleSearch != "" {
		singleSearchRegex, err = regexp.Compile(opts.SingleSearch)
		if err != nil {
			return fmt.Errorf("unable to compile regex: %s, %v", opts.SingleSearch, err)
		}
	}

	if opts.Entropy > 8 {
		return fmt.Errorf("The maximum level of entropy is 8")
	}

	return nil
}

// loadToml loads of the toml config containing regexes and whitelists.
// This function will first look if the configPath is set and load the config
// from that file. Otherwise will then look for the path set by the GITHLEAKS_CONIFG
// env var. If that is not set, then gitleaks will continue with the default configs
// specified by the const var at the top `defaultConfig`
func loadToml() error {
	var (
		config     Config
		configPath string
	)
	if opts.ConfigPath != "" {
		configPath = opts.ConfigPath
		_, err := os.Stat(configPath)
		if err != nil {
			return fmt.Errorf("no gitleaks config at %s", configPath)
		}
	} else {
		configPath = os.Getenv("GITLEAKS_CONFIG")
	}

	if configPath != "" {
		if _, err := toml.DecodeFile(configPath, &config); err != nil {
			return fmt.Errorf("problem loading config: %v", err)
		}
	} else {
		_, err := toml.Decode(defaultConfig, &config)
		if err != nil {
			return fmt.Errorf("problem loading default config: %v", err)
		}
	}

	if singleSearchRegex != nil {
		regexes["singleSearch"] = singleSearchRegex
	} else {
		for _, regex := range config.Regexes {
			regexes[regex.Description] = regexp.MustCompile(regex.Regex)
		}
	}
	whiteListBranches = config.Whitelist.Branches
	whiteListRepos = config.Whitelist.Repos
	whiteListCommits = make(map[string]bool)
	for _, commit := range config.Whitelist.Commits {
		whiteListCommits[commit] = true
	}
	for _, regex := range config.Whitelist.Files {
		whiteListFiles = append(whiteListFiles, regexp.MustCompile(regex))
	}
	for _, regex := range config.Whitelist.Regexes {
		whiteListRegexes = append(whiteListRegexes, regexp.MustCompile(regex))
	}

	return nil
}

// getSSHAuth return an ssh auth use by go-git to clone repos behind authentication.
// If --ssh-key is set then it will attempt to load the key from that path. If not,
// gitleaks will use the default $HOME/.ssh/id_rsa key
func getSSHAuth() (*ssh.PublicKeys, error) {
	var (
		sshKeyPath string
	)
	if opts.SSHKey != "" {
		sshKeyPath = opts.SSHKey
	} else {
		c, _ := user.Current()
		sshKeyPath = fmt.Sprintf("%s/.ssh/id_rsa", c.HomeDir)
	}
	sshAuth, err := ssh.NewPublicKeysFromFile("git", sshKeyPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to generate ssh key: %v", err)
	}
	return sshAuth, err
}

func (leak Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}
