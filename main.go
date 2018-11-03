package main

import (
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/src-d/go-git.v4/plumbing"

	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
	"gopkg.in/src-d/go-git.v4/storage/memory"

	"github.com/BurntSushi/toml"
	"github.com/google/go-github/github"
	"github.com/hako/durafmt"
	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
)

// Leak represents a leaked secret or regex match.
type Leak struct {
	Line     string    `json:"line"`
	Commit   string    `json:"commit"`
	Offender string    `json:"offender"`
	Type     string    `json:"reason"`
	Message  string    `json:"commitMsg"`
	Author   string    `json:"author"`
	File     string    `json:"file"`
	Branch   string    `json:"branch"`
	Repo     string    `json:"repo"`
	Date     time.Time `json:"date"`
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
	Repo       string `short:"r" long:"repo" description:"Repo url to audit"`
	GithubUser string `long:"github-user" description:"Github user to audit"`
	GithubOrg  string `long:"github-org" description:"Github organization to audit"`
	GithubURL  string `long:"github-url" default:"https://api.github.com/" description:"GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/"`
	GithubPR   string `long:"github-pr" description:"Github PR url to audit. This does not clone the repo. GITHUB_TOKEN must be set"`

	/*
		TODO:
		GitLabUser string `long:"gitlab-user" description:"User url to audit"`
		GitLabOrg  string `long:"gitlab-org" description:"Organization url to audit"`
	*/

	Commit string `short:"c" long:"commit" description:"sha of commit to stop at"`
	Depth  int    `long:"depth" description:"maximum commit depth"`

	// local target option
	RepoPath  string `long:"repo-path" description:"Path to repo"`
	OwnerPath string `long:"owner-path" description:"Path to owner directory (repos discovered)"`

	// Process options
	Threads      int     `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	Disk         bool    `long:"disk" description:"Clones repo(s) to disk"`
	SingleSearch string  `long:"single-search" description:"single regular expression to search for"`
	ConfigPath   string  `long:"config" description:"path to gitleaks config"`
	SSHKey       string  `long:"ssh-key" description:"path to ssh key"`
	ExcludeForks bool    `long:"exclude-forks" description:"exclude forks for organization/user audits"`
	Entropy      float64 `long:"entropy" short:"e" description:"Include entropy checks during audit. Entropy scale: 0.0(no entropy) - 8.0(max entropy)"`
	// TODO: IncludeMessages  string `long:"messages" description:"include commit messages in audit"`

	// Output options
	Log          string `short:"l" long:"log" description:"log level"`
	Verbose      bool   `short:"v" long:"verbose" description:"Show verbose output from gitleaks audit"`
	Report       string `long:"report" description:"path to write report file. Needs to be csv or json"`
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
		Files   []string
		Regexes []string
		Commits []string
		Repos   []string
	}
	Misc struct {
		Entropy []string
	}
}

type gitDiff struct {
	content      string
	commit       *object.Commit
	filePath     string
	repoName     string
	githubCommit *github.RepositoryCommit
	sha          string
	message      string
	author       string
	date         time.Time
}

type entropyRange struct {
	v1 float64
	v2 float64
}

const defaultGithubURL = "https://api.github.com/"
const version = "1.19.0"
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
description = "PKCS8"
regex = '''-----BEGIN PRIVATE KEY-----'''
[[regexes]]
description = "RSA"
regex = '''-----BEGIN RSA PRIVATE KEY-----'''
[[regexes]]
description = "SSH"
regex = '''-----BEGIN OPENSSH PRIVATE KEY-----'''
[[regexes]]
description = "PGP"
regex = '''-----BEGIN PGP PRIVATE KEY BLOCK-----'''
[[regexes]]
description = "Facebook"
regex = '''(?i)facebook(.{0,4})?['\"][0-9a-f]{32}['\"]'''
[[regexes]]
description = "Twitter"
regex = '''(?i)twitter(.{0,4})?['\"][0-9a-zA-Z]{35,44}['\"]'''
[[regexes]]
description = "Github"
regex = '''(?i)github(.{0,4})?['\"][0-9a-zA-Z]{35,40}['\"]'''
[[regexes]]
description = "Slack"
regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''

[whitelist]
#commits = [
#  "BADHA5H1",
#  "BADHA5H2",
#]
#repos = [
#	"mygoodrepo"
#]
[misc]
#entropy = [
#	"3.3-4.30"
#	"6.0-8.0
#]
`

var (
	opts              Options
	regexes           map[string]*regexp.Regexp
	singleSearchRegex *regexp.Regexp
	whiteListRegexes  []*regexp.Regexp
	whiteListFiles    []*regexp.Regexp
	whiteListCommits  map[string]bool
	whiteListRepos    []*regexp.Regexp
	entropyRanges     []entropyRange
	fileDiffRegex     *regexp.Regexp
	sshAuth           *ssh.PublicKeys
	dir               string
	threads           int
	totalCommits      int64
	commitMap         = make(map[string]bool)
	cMutex            = &sync.Mutex{}
)

func init() {
	log.SetOutput(os.Stdout)
	// threads = runtime.GOMAXPROCS(0) / 2
	threads = 1
	regexes = make(map[string]*regexp.Regexp)
	whiteListCommits = make(map[string]bool)
}

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
	}

	if len(os.Args) == 1 {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}

	if opts.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	if opts.SampleConfig {
		fmt.Println(defaultConfig)
		os.Exit(0)
	}
	now := time.Now()
	leaks, err := run()
	if err != nil {
		if strings.Contains(err.Error(), "whitelisted") {
			log.Info(err.Error())
			os.Exit(0)
		}
		log.Error(err)
		os.Exit(errExit)
	}
	if opts.Report != "" {
		writeReport(leaks)
	}
	if len(leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(leaks), totalCommits, durafmt.Parse(time.Now().Sub(now)).String())
		os.Exit(leakExit)
	} else {
		log.Infof("%d leaks detected. %d commits inspected in %s", len(leaks), totalCommits, durafmt.Parse(time.Now().Sub(now)).String())
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
	sshAuth, err = getSSHAuth()
	if err != nil {
		return leaks, err
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
		// Audit a github owner -- a user or organization.
		leaks, err = auditGithubRepos()
		if err != nil {
			return leaks, err
		}
	} else if opts.GithubPR != "" {
		return auditGithubPR()
	}
	return leaks, nil
}

// writeReport writes a report to a file specified in the --report= option.
// Default format for report is JSON. You can use the --csv option to write the report as a csv
func writeReport(leaks []Leak) error {
	var err error
	log.Infof("writing report to %s", opts.Report)
	if strings.HasSuffix(opts.Report, ".csv") {
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"repo", "line", "commit", "offender", "reason", "commitMsg", "author", "file", "branch", "date"})
		for _, leak := range leaks {
			w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Type, leak.Message, leak.Author, leak.File, leak.Branch, leak.Date.Format(time.RFC3339)})
		}
		w.Flush()
	} else {
		reportJSON, _ := json.MarshalIndent(leaks, "", "\t")
		err = ioutil.WriteFile(opts.Report, reportJSON, 0644)
	}
	return err
}

// cloneRepo clones a repo to memory(default) or to disk if the --disk option is set.
func cloneRepo() (*RepoDescriptor, error) {
	var (
		err  error
		repo *git.Repository
	)
	// check if whitelist
	for _, re := range whiteListRepos {
		if re.FindString(opts.Repo) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", opts.Repo)
		}
	}
	if opts.Disk {
		log.Infof("cloning %s", opts.Repo)
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if strings.HasPrefix(opts.Repo, "git") {
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
		log.Infof("opening %s", opts.RepoPath)
		repo, err = git.PlainOpen(opts.RepoPath)
	} else {
		log.Infof("cloning %s", opts.Repo)
		if strings.HasPrefix(opts.Repo, "git") {
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
	for _, re := range whiteListRepos {
		if re.FindString(repo.name) != "" {
			return leaks, fmt.Errorf("skipping %s, whitelisted", repo.name)
		}
	}

	// clear commit cache
	commitMap = make(map[string]bool)

	refs, err := repo.repository.Storer.IterReferences()
	if err != nil {
		return leaks, err
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Name().IsTag() {
			return nil
		}
		branchLeaks := auditGitReference(repo, ref)
		for _, leak := range branchLeaks {
			leaks = append(leaks, leak)
		}
		return nil
	})
	return leaks, err
}

// auditGitReference beings the audit for a git reference. This function will
// traverse the git reference and audit each line of each diff.
func auditGitReference(repo *RepoDescriptor, ref *plumbing.Reference) []Leak {
	var (
		err         error
		repoName    string
		leaks       []Leak
		commitCount int
		commitWg    sync.WaitGroup
		mutex       = &sync.Mutex{}
		semaphore   chan bool
	)
	repoName = repo.name
	if opts.Threads != 0 {
		threads = opts.Threads
	}
	if opts.RepoPath != "" {
		threads = 1
	}
	semaphore = make(chan bool, threads)

	cIter, err := repo.repository.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil
	}
	err = cIter.ForEach(func(c *object.Commit) error {
		if commitMap[c.Hash.String()] {
			return nil
		}
		cMutex.Lock()
		commitMap[c.Hash.String()] = true
		cMutex.Unlock()
		if c == nil || c.Hash.String() == opts.Commit || (opts.Depth != 0 && commitCount == opts.Depth) {
			cIter.Close()
			return errors.New("ErrStop")
		}
		commitCount = commitCount + 1
		totalCommits = totalCommits + 1
		if whiteListCommits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}

		err = c.Parents().ForEach(func(parent *object.Commit) error {
			commitWg.Add(1)
			semaphore <- true
			go func(c *object.Commit, parent *object.Commit) {
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
				patch, err := c.Patch(parent)
				if err != nil {
					log.Warnf("problem generating patch for commit: %s\n", c.Hash.String())
					return
				}
				for _, f := range patch.FilePatches() {
					if f.IsBinary() {
						continue
					}
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
							diff := gitDiff{
								repoName: repoName,
								filePath: filePath,
								content:  chunk.Content(),
								sha:      c.Hash.String(),
								author:   c.Author.String(),
								message:  c.Message,
								date:     c.Author.When,
							}
							chunkLeaks := inspect(diff)
							for _, leak := range chunkLeaks {
								mutex.Lock()
								leaks = append(leaks, leak)
								mutex.Unlock()
							}
						}
					}
				}
			}(c, parent)
			return nil
		})
		return nil
	})
	commitWg.Wait()
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

		if opts.Entropy > 0 || len(entropyRanges) != 0 {
			entropyLeak := false
			words := strings.Fields(line)
			for _, word := range words {
				entropy := getShannonEntropy(word)
				if entropy >= opts.Entropy && len(entropyRanges) == 0 {
					entropyLeak = true
				}
				if len(entropyRanges) != 0 {
					for _, eR := range entropyRanges {
						if entropy > eR.v1 && entropy < eR.v2 {
							entropyLeak = true
						}
					}
				}
				if entropyLeak {
					leaks = addLeak(leaks, line, word, fmt.Sprintf("Entropy: %.2f", entropy), diff)
					entropyLeak = false
				}
			}
		}
	}
	return leaks
}

// addLeak is helper for func inspect() to append leaks if found during a diff check.
func addLeak(leaks []Leak, line string, offender string, leakType string, diff gitDiff) []Leak {
	leak := Leak{
		Line:     line,
		Commit:   diff.sha,
		Offender: offender,
		Type:     leakType,
		Author:   diff.author,
		File:     diff.filePath,
		Repo:     diff.repoName,
		Message:  diff.message,
		Date:     diff.date,
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
	}

	if opts.Threads > runtime.GOMAXPROCS(0) {
		return fmt.Errorf("%d available threads", runtime.GOMAXPROCS(0))
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
	if opts.Report != "" {
		if !strings.HasSuffix(opts.Report, ".json") && !strings.HasSuffix(opts.Report, ".csv") {
			return fmt.Errorf("Report should be a .json or .csv file")
		}
		dirPath := filepath.Dir(opts.Report)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist", dirPath)
		}
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

	if len(config.Misc.Entropy) != 0 {
		err := entropyLimits(config.Misc.Entropy)
		if err != nil {
			return err
		}
	}

	if singleSearchRegex != nil {
		regexes["singleSearch"] = singleSearchRegex
	} else {
		for _, regex := range config.Regexes {
			regexes[regex.Description] = regexp.MustCompile(regex.Regex)
		}
	}
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
	for _, regex := range config.Whitelist.Repos {
		whiteListRepos = append(whiteListRepos, regexp.MustCompile(regex))
	}

	return nil
}

// entropyLimits hydrates entropyRanges which allows for fine tuning entropy checking
func entropyLimits(entropyLimitStr []string) error {
	for _, span := range entropyLimitStr {
		split := strings.Split(span, "-")
		v1, err := strconv.ParseFloat(split[0], 64)
		if err != nil {
			return err
		}
		v2, err := strconv.ParseFloat(split[1], 64)
		if err != nil {
			return err
		}
		if v1 > v2 {
			return fmt.Errorf("entropy range must be ascending")
		}
		r := entropyRange{
			v1: v1,
			v2: v2,
		}
		if r.v1 > 8.0 || r.v1 < 0.0 || r.v2 > 8.0 || r.v2 < 0.0 {
			return fmt.Errorf("invalid entropy ranges, must be within 0.0-8.0")
		}
		entropyRanges = append(entropyRanges, r)
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
		// try grabbing default
		c, err := user.Current()
		if err != nil {
			return nil, nil
		}
		sshKeyPath = fmt.Sprintf("%s/.ssh/id_rsa", c.HomeDir)
	}
	sshAuth, err := ssh.NewPublicKeysFromFile("git", sshKeyPath, "")
	if err != nil {
		if strings.HasPrefix(opts.Repo, "git") {
			// if you are attempting to clone a git repo via ssh and supply a bad ssh key,
			// the clone will fail.
			return nil, fmt.Errorf("unable to generate ssh key: %v", err)
		}
	}
	return sshAuth, nil
}

func (leak Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}
