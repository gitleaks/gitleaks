package main

import (
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/src-d/go-git.v4/plumbing"

	"github.com/google/go-github/github"
	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4"
	diffType "gopkg.in/src-d/go-git.v4/plumbing/format/diff"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/storer"
	"gopkg.in/src-d/go-git.v4/storage/memory"
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

const defaultGithubURL = "https://api.github.com/"
const version = "1.24.0"
const errExit = 2
const leakExit = 1

var (
	opts              *Options
	config            *Config
	singleSearchRegex *regexp.Regexp
	dir               string
	threads           int
	totalCommits      int64
	commitMap         = make(map[string]bool)
	cMutex            = &sync.Mutex{}
	auditDone         bool
)

func init() {
	log.SetOutput(os.Stdout)
	// threads = runtime.GOMAXPROCS(0) / 2
	threads = 1
}

func main() {
	var err error
	opts, err = setupOpts()
	if err != nil {
		log.Fatal(err)
	}
	config, err = newConfig()
	if err != nil {
		log.Fatal(err)
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
	var (
		leaks []Leak
		err   error
	)

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
	} else if opts.GitLabOrg != "" || opts.GitLabUser != "" {
		leaks, err = auditGitlabRepos()
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

	if len(leaks) == 0 {
		return nil
	}

	log.Infof("writing report to %s", opts.Report)
	if strings.HasSuffix(opts.Report, ".csv") {
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"repo", "line", "commit", "offender", "reason", "commitMsg", "author", "file", "date"})
		for _, leak := range leaks {
			w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Type, leak.Message, leak.Author, leak.File, leak.Date.Format(time.RFC3339)})
		}
		w.Flush()
	} else {
		var (
			f       *os.File
			encoder *json.Encoder
		)
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		encoder = json.NewEncoder(f)
		encoder.SetIndent("", "\t")
		if _, err := f.WriteString("[\n"); err != nil {
			return err
		}
		for i := 0; i < len(leaks); i++ {
			if err := encoder.Encode(leaks[i]); err != nil {
				return err
			}
			// for all but the last leak, seek back and overwrite the newline appended by Encode() with comma & newline
			if i+1 < len(leaks) {
				if _, err := f.Seek(-1, 1); err != nil {
					return err
				}
				if _, err := f.WriteString(",\n"); err != nil {
					return err
				}
			}
		}
		if _, err := f.WriteString("]"); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			log.Error(err)
			return err
		}
	}
	return err
}

// cloneRepo clones a repo to memory(default) or to disk if the --disk option is set.
func cloneRepo() (*RepoDescriptor, error) {
	var (
		err  error
		repo *git.Repository
	)
	// check if repo is whitelisted
	for _, re := range config.WhiteList.repos {
		if re.FindString(opts.Repo) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", opts.Repo)
		}
	}

	// check if cloning to disk
	if opts.Disk {
		log.Infof("cloning %s to disk", opts.Repo)
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if strings.HasPrefix(opts.Repo, "git") {
			// private
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
			})
		} else {
			// non-private
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	} else if opts.RepoPath != "" {
		// local repo
		log.Infof("opening %s", opts.RepoPath)
		repo, err = git.PlainOpen(opts.RepoPath)
	} else {
		// cloning to memory
		log.Infof("cloning %s", opts.Repo)
		if strings.HasPrefix(opts.Repo, "git") {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
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

// auditGitRepo beings an audit on a git repository
func auditGitRepo(repo *RepoDescriptor) ([]Leak, error) {
	var (
		err   error
		leaks []Leak
	)
	for _, re := range config.WhiteList.repos {
		if re.FindString(repo.name) != "" {
			return leaks, fmt.Errorf("skipping %s, whitelisted", repo.name)
		}
	}

	// check if target contains an external gitleaks toml
	if opts.RepoConfig {
		err := config.updateFromRepo(repo)
		if err != nil {
			return leaks, nil
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
		commitCount int64
		commitWg    sync.WaitGroup
		mutex       = &sync.Mutex{}
		semaphore   chan bool
	)
	if auditDone {
		return nil
	}
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
		if c == nil || (opts.Depth != 0 && commitCount == opts.Depth) || auditDone {
			if commitCount == opts.Depth {
				auditDone = true
			}
			return storer.ErrStop
		}
		commitCount = commitCount + 1
		if config.WhiteList.commits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}

		// commits w/o parent (root of git the git ref) or option for single commit is not empty str
		if len(c.ParentHashes) == 0 || opts.Commit == c.Hash.String() {
			if commitMap[c.Hash.String()] {
				return nil
			}

			if opts.Commit == c.Hash.String() {
				auditDone = true
			}

			cMutex.Lock()
			commitMap[c.Hash.String()] = true
			cMutex.Unlock()
			totalCommits = totalCommits + 1

			fIter, err := c.Files()
			if err != nil {
				return nil
			}
			err = fIter.ForEach(func(f *object.File) error {
				bin, err := f.IsBinary()
				if bin || err != nil {
					return nil
				}
				for _, re := range config.WhiteList.files {
					if re.FindString(f.Name) != "" {
						log.Debugf("skipping whitelisted file (matched regex '%s'): %s", re.String(), f.Name)
						return nil
					}
				}
				content, err := f.Contents()
				if err != nil {
					return nil
				}
				diff := gitDiff{
					repoName: repoName,
					filePath: f.Name,
					content:  content,
					sha:      c.Hash.String(),
					author:   c.Author.String(),
					message:  strings.Replace(c.Message, "\n", " ", -1),
					date:     c.Author.When,
				}
				fileLeaks := inspect(diff)
				mutex.Lock()
				leaks = append(leaks, fileLeaks...)
				mutex.Unlock()
				return nil
			})
			return nil
		}

		// single commit
		if opts.Commit != "" {
			return nil
		}

		skipCount := false
		err = c.Parents().ForEach(func(parent *object.Commit) error {
			// check if we've seen this diff before
			if commitMap[c.Hash.String()+parent.Hash.String()] {
				return nil
			}
			cMutex.Lock()
			commitMap[c.Hash.String()+parent.Hash.String()] = true
			cMutex.Unlock()

			if !skipCount {
				totalCommits = totalCommits + 1
				skipCount = true
			}

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
						log.Warnf("recovering from panic on commit %s, likely large diff causing panic", c.Hash.String())
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
					for _, re := range config.WhiteList.files {
						if re.FindString(filePath) != "" {
							log.Debugf("skipping whitelisted file (matched regex '%s'): %s", re.String(), filePath)
							skipFile = true
							break
						}
					}
					if skipFile {
						continue
					}
					chunks := f.Chunks()
					for _, chunk := range chunks {
						if chunk.Type() == diffType.Add || chunk.Type() == diffType.Delete {
							diff := gitDiff{
								repoName: repoName,
								filePath: filePath,
								content:  chunk.Content(),
								sha:      c.Hash.String(),
								author:   c.Author.String(),
								message:  strings.Replace(c.Message, "\n", " ", -1),
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

		// stop audit if we are at commitStop
		if c.Hash.String() == opts.CommitStop {
			auditDone = true
			return storer.ErrStop
		}

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
	var (
		leaks    []Leak
		skipLine bool
	)

	lines := strings.Split(diff.content, "\n")

	for _, line := range lines {
		skipLine = false
		for _, re := range config.Regexes {
			match := re.regex.FindString(line)
			if match == "" {
				continue
			}
			if skipLine = isLineWhitelisted(line); skipLine {
				break
			}
			leaks = addLeak(leaks, line, match, re.description, diff)
		}

		if !skipLine && (opts.Entropy > 0 || len(config.Entropy.entropyRanges) != 0) {
			words := strings.Fields(line)
			for _, word := range words {
				entropy := getShannonEntropy(word)
				// Only check entropyRegexes and whiteListRegexes once per line, and only if an entropy leak type
				// was found above, since regex checks are expensive.
				if !entropyIsHighEnough(entropy) {
					continue
				}
				// If either the line is whitelisted or the line fails the noiseReduction check (when enabled),
				// then we can skip checking the rest of the line for high entropy words.
				if skipLine = !highEntropyLineIsALeak(line) || isLineWhitelisted(line); skipLine {
					break
				}
				leaks = addLeak(leaks, line, word, fmt.Sprintf("Entropy: %.2f", entropy), diff)
			}
		}
	}
	return leaks
}

// isLineWhitelisted returns true iff the line is matched by at least one of the whiteListRegexes.
func isLineWhitelisted(line string) bool {
	for _, wRe := range config.WhiteList.regexes {
		whitelistMatch := wRe.FindString(line)
		if whitelistMatch != "" {
			return true
		}
	}
	return false
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
		leak.Line = strings.Replace(line, offender, "REDACTED", -1)
	}

	if opts.Verbose {
		leak.log()
	}

	leaks = append(leaks, leak)
	return leaks
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

func (leak Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}
