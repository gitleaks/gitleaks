package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
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

// Leak represents a leaked secret or regex match. This will be output to stdout and/or the report
type Leak struct {
	Line     string `json:"line"`
	Commit   string `json:"commit"`
	Offender string `json:"offender"`
	Type     string `json:"reason"`
	Message  string `json:"commitMsg"`
	Author   string `json:"author"`
	File     string `json:"file"`
	Branch   string `json:"branch"`
}

// Repo contains the actual git repository and meta data about the repo
type Repo struct {
	path       string
	url        string
	name       string
	leaks      []Leak
	repository *git.Repository
}

// Owner contains a collection of repos. This could represent an org or user.
type Owner struct {
	path  string
	url   string
	repos []Repo
}

// Options for gitleaks
type Options struct {
	// remote target options
	Repo           string `short:"r" long:"repo" description:"Repo url to audit"`
	GithubUser     string `long:"github-user" description:"User url to audit"`
	GithubOrg      string `long:"github-org" description:"Organization url to audit"`
	GithubURL      string `long:"github-url" default:"https://api.github.com/" description:"GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/"`
	IncludePrivate bool   `short:"p" long:"private" description:"Include private repos in audit"`

	/*
		TODO:
		GitLabUser string `long:"gitlab-user" description:"User url to audit"`
		GitLabOrg  string `long:"gitlab-org" description:"Organization url to audit"`
	*/

	Branch string `short:"b" long:"branch" description:"branch name to audit (defaults to HEAD)"`
	Commit string `short:"c" long:"commit" description:"sha of commit to stop at"`

	// local target option
	RepoPath  string `long:"repo-path" description:"Path to repo"`
	OwnerPath string `long:"owner-path" description:"Path to owner directory (repos discovered)"`

	// Process options
	MaxGoRoutines int    `long:"max-go" description:"Maximum number of concurrent go-routines gitleaks spawns"`
	Disk          bool   `long:"disk" description:"Clones repo(s) to disk"`
	AuditAllRefs  bool   `long:"all-refs" description:"run audit on all refs"`
	SingleSearch  string `long:"single-search" description:"single regular expression to search for"`
	ConfigPath    string `long:"config" description:"path to gitleaks config"`
	SSHKey        string `long:"ssh-key" description:"path to ssh key"`
	// TODO: IncludeMessages  string `long:"messages" description:"include commit messages in audit"`

	// Output options
	Log     string `short:"l" long:"log" description:"log level"`
	Verbose bool   `short:"v" long:"verbose" description:"Show verbose output from gitleaks audit"`
	Report  string `long:"report" description:"path to write report file"`
	Redact  bool   `long:"redact" description:"redact secrets from log messages and report"`
	Version bool   `long:"version" description:"version number"`
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
	}
}

const defaultGithubURL = "https://api.github.com/"
const version = "1.1.2"
const defaultConfig = `
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
`

var (
	opts              Options
	regexes           map[string]*regexp.Regexp
	singleSearchRegex *regexp.Regexp
	whiteListRegexes  []*regexp.Regexp
	whiteListFiles    []*regexp.Regexp
	whiteListCommits  map[string]bool
	whiteListBranches []string
	fileDiffRegex     *regexp.Regexp
	sshAuth           *ssh.PublicKeys
	dir               string
)

func init() {
	log.SetOutput(os.Stdout)
	regexes = make(map[string]*regexp.Regexp)
	whiteListCommits = make(map[string]bool)
}

func main() {
	var (
		leaks []Leak
		repos []Repo
	)
	_, err := flags.Parse(&opts)
	if opts.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	if err != nil {
		os.Exit(1)
	}
	setLogs()

	err = optsGuard()
	if err != nil {
		log.Fatal(err)
	}

	err = loadToml()
	if err != nil {
		log.Fatal(err)
	}

	if opts.IncludePrivate {
		// if including private repos use ssh as authentication
		sshAuth, err = getSSHAuth()
		if err != nil {
			log.Fatal(err)
		}
	}

	if opts.Disk {
		// temporary directory where all the gitleaks plain clones will reside
		dir, err = ioutil.TempDir("", "gitleaks")
		defer os.RemoveAll(dir)
		if err != nil {
			log.Fatal(err)
		}
	}

	// start audits
	if opts.Repo != "" || opts.RepoPath != "" {
		r, err := getRepo()
		if err != nil {
			log.Fatal(err)
		}
		repos = append(repos, r)
	} else if ownerTarget() {
		repos, err = getOwnerRepos()
	}
	for _, r := range repos {
		l, err := auditRepo(r.repository)
		if len(l) == 0 {
			log.Infof("no leaks found for repo %s", r.name)
		} else {
			log.Warnf("leaks found for repo %s", r.name)
		}
		if err != nil {
			log.Fatal(err)
		}
		leaks = append(leaks, l...)
	}

	if opts.Report != "" {
		writeReport(leaks)
	}

	if len(leaks) != 0 {
		log.Debug("leaks detected")
		os.Exit(1)
	}
}

// writeReport writes a report to opts.Report in JSON.
// TODO support yaml
func writeReport(leaks []Leak) error {
	log.Info("writing report to %s", opts.Report)
	reportJSON, _ := json.MarshalIndent(leaks, "", "\t")
	err := ioutil.WriteFile(opts.Report, reportJSON, 0644)
	return err
}

// getRepo is responsible for cloning a repo in-memory or to disk, or opening a local repo and creating
// a repo object
func getRepo() (Repo, error) {
	var (
		err error
		r   *git.Repository
	)

	log.Infof("cloning %s", opts.Repo)
	if opts.Disk {
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if opts.IncludePrivate {
			r, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     sshAuth,
			})
		} else {
			r, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	} else if opts.RepoPath != "" {
		// use existing repo
		r, err = git.PlainOpen(opts.RepoPath)
	} else {
		if opts.IncludePrivate {
			r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     sshAuth,
			})
		} else {
			r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	}
	if err != nil {
		return Repo{}, err
	}
	return Repo{
		repository: r,
		path:       opts.RepoPath,
		url:        opts.Repo,
		name:       filepath.Base(opts.Repo),
	}, nil
}

// auditRef audits a git reference
// TODO: need to add a layer of parallelism here and a cache for parent+child commits so we don't
// double dip
func auditRef(r *git.Repository, ref *plumbing.Reference, commitWg *sync.WaitGroup, commitChan chan []Leak) error {
	var (
		err             error
		prevCommit      *object.Commit
		limitGoRoutines bool
		semaphore       chan bool
	)

	// goroutine limiting
	if opts.MaxGoRoutines != 0 {
		semaphore = make(chan bool, opts.MaxGoRoutines)
		limitGoRoutines = true
	}
	cIter, err := r.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return err
	}
	err = cIter.ForEach(func(c *object.Commit) error {
		if c.Hash.String() == opts.Commit {
			cIter.Close()
		}
		if whiteListCommits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}
		if limitGoRoutines {
			semaphore <- true
		}
		if prevCommit == nil {
			prevCommit = c
		}

		commitWg.Add(1)
		go func(c *object.Commit, prevCommit *object.Commit) {
			var (
				leaks    []Leak
				filePath string
				skipFile bool
			)
			patch, _ := c.Patch(prevCommit)
			for _, f := range patch.FilePatches() {
				skipFile = false
				from, to := f.Files()
				filePath = "???"
				if from != nil {
					filePath = from.Path()
				} else if to != nil {
					filePath = to.Path()
				}
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
						// only check if adding or removing
						leaks = append(leaks, checkDiff(chunk.Content(), prevCommit, filePath, string(ref.Name()))...)
					}
				}
			}

			if limitGoRoutines {
				<-semaphore
			}
			commitChan <- leaks
		}(c, prevCommit)

		prevCommit = c
		return nil
	})
	return nil
}

// auditRepo performs an audit on a repository checking for regex matching and ignoring
// files and regexes that are whitelisted
func auditRepo(r *git.Repository) ([]Leak, error) {
	var (
		err      error
		leaks    []Leak
		commitWg sync.WaitGroup
	)

	ref, err := r.Head()
	if err != nil {
		return leaks, err
	}

	// leak messaging
	commitChan := make(chan []Leak, 1)

	if opts.AuditAllRefs {
		skipBranch := false
		refs, err := r.Storer.IterReferences()
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
			auditRef(r, ref, &commitWg, commitChan)
			return nil
		})
	} else {
		auditRef(r, ref, &commitWg, commitChan)
	}

	go func() {
		for commitLeaks := range commitChan {
			if commitLeaks != nil {
				for _, leak := range commitLeaks {
					leaks = append(leaks, leak)
				}

			}
			commitWg.Done()
		}
	}()

	commitWg.Wait()
	return leaks, err
}

// checkDiff accepts a string diff and commit object then performs a
// regex check
func checkDiff(diff string, commit *object.Commit, filePath string, branch string) []Leak {
	lines := strings.Split(diff, "\n")
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

			leak := Leak{
				Line:     line,
				Commit:   commit.Hash.String(),
				Offender: match,
				Type:     leakType,
				Message:  commit.Message,
				Author:   commit.Author.String(),
				File:     filePath,
				Branch:   branch,
			}
			if opts.Verbose {
				leak.log()
			}
			if opts.Redact {
				leak.Offender = "REDACTED"
			}
			leaks = append(leaks, leak)
		}
	}
	return leaks
}

// auditOwner audits all of the owner's(user or org) repos
func getOwnerRepos() ([]Repo, error) {
	var (
		err   error
		repos []Repo
	)
	ctx := context.Background()

	if opts.OwnerPath != "" {
		repos, err = discoverRepos(opts.OwnerPath)
	} else if opts.GithubOrg != "" {
		githubClient := github.NewClient(githubToken())
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}

		githubOptions := github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{PerPage: 10},
		}
		repos, err = getOrgGithubRepos(ctx, &githubOptions, githubClient)
	} else if opts.GithubUser != "" {
		githubClient := github.NewClient(githubToken())
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}

		githubOptions := github.RepositoryListOptions{
			Affiliation: "owner",
			ListOptions: github.ListOptions{
				PerPage: 10,
			},
		}
		repos, err = getUserGithubRepos(ctx, &githubOptions, githubClient)
	}

	return repos, err
}

// getUserGithubRepos grabs all github user's public and/or private repos
func getUserGithubRepos(ctx context.Context, listOpts *github.RepositoryListOptions, client *github.Client) ([]Repo, error) {
	var (
		err   error
		repos []Repo
		r     *git.Repository
		rs    []*github.Repository
		resp  *github.Response
	)

	for {
		if opts.IncludePrivate {
			rs, resp, err = client.Repositories.List(ctx, "", listOpts)
		} else {
			rs, resp, err = client.Repositories.List(ctx, opts.GithubUser, listOpts)
		}

		for _, rDesc := range rs {
			log.Infof("cloning: %s", *rDesc.Name)
			if opts.Disk {
				ownerDir, err := ioutil.TempDir(dir, opts.GithubUser)
				if err != nil {
					return repos, fmt.Errorf("unable to generater owner temp dir: %v", err)
				}
				if opts.IncludePrivate {
					r, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *rDesc.Name), false, &git.CloneOptions{
						URL:  *rDesc.SSHURL,
						Auth: sshAuth,
					})
				} else {
					r, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *rDesc.Name), false, &git.CloneOptions{
						URL: *rDesc.CloneURL,
					})

				}
			} else {
				if opts.IncludePrivate {
					r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
						URL:  *rDesc.SSHURL,
						Auth: sshAuth,
					})
				} else {
					r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
						URL: *rDesc.CloneURL,
					})
				}
			}
			if err != nil {
				return repos, fmt.Errorf("problem cloning %s -- %v", *rDesc.Name, err)
			}
			repos = append(repos, Repo{
				name:       *rDesc.Name,
				url:        *rDesc.SSHURL,
				repository: r,
			})
		}
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}
	return repos, err
}

// getOrgGithubRepos grabs all of org's public and/or private repos
func getOrgGithubRepos(ctx context.Context, listOpts *github.RepositoryListByOrgOptions, client *github.Client) ([]Repo, error) {
	var (
		err      error
		repos    []Repo
		r        *git.Repository
		ownerDir string
	)

	for {
		rs, resp, err := client.Repositories.ListByOrg(ctx, opts.GithubOrg, listOpts)
		for _, rDesc := range rs {
			log.Infof("cloning: %s", *rDesc.Name)
			if opts.Disk {
				ownerDir, err = ioutil.TempDir(dir, opts.GithubUser)
				if err != nil {
					return repos, fmt.Errorf("unable to generater owner temp dir: %v", err)
				}
				if opts.IncludePrivate {
					if sshAuth == nil {
						return nil, fmt.Errorf("no ssh auth available")
					}
					r, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *rDesc.Name), false, &git.CloneOptions{
						URL:  *rDesc.SSHURL,
						Auth: sshAuth,
					})
				} else {
					r, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *rDesc.Name), false, &git.CloneOptions{
						URL: *rDesc.CloneURL,
					})

				}
			} else {
				if opts.IncludePrivate {
					if sshAuth == nil {
						return nil, fmt.Errorf("no ssh auth available")
					}
					r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
						URL:  *rDesc.SSHURL,
						Auth: sshAuth,
					})
				} else {
					r, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
						URL: *rDesc.CloneURL,
					})
				}
			}
			if err != nil {
				return nil, err
			}
			repos = append(repos, Repo{
				url:        *rDesc.SSHURL,
				name:       *rDesc.Name,
				repository: r,
			})
		}
		if err != nil {
			return nil, err
		} else if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return repos, err
}

// githubToken returns a oauth2 client for the github api to consume
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
// contain a .git file then that repo will be added
func discoverRepos(ownerPath string) ([]Repo, error) {
	var (
		err   error
		repos []Repo
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
			repos = append(repos, Repo{
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

	return nil
}

// loadToml loads of the toml config containing regexes and whitelists
// 1. look for config path
// 2. two, look for gitleaks config env var
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

	// load up regexes
	if singleSearchRegex != nil {
		// single search takes precedence over default regex
		regexes["singleSearch"] = singleSearchRegex
	} else {
		for _, regex := range config.Regexes {
			regexes[regex.Description] = regexp.MustCompile(regex.Regex)
		}
	}
	whiteListBranches = config.Whitelist.Branches
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

// ownerTarget checks if we are dealing with a remote owner
func ownerTarget() bool {
	if opts.GithubOrg != "" ||
		opts.GithubUser != "" ||
		opts.OwnerPath != "" {
		return true
	}
	return false
}

// getSSHAuth generates ssh auth
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

func (leak *Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}
