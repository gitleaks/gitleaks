package gitleaks

import (
	"crypto/md5"
	"fmt"
	"github.com/hako/durafmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	diffType "gopkg.in/src-d/go-git.v4/plumbing/format/diff"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/storer"
	gitHttp "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/memory"
	"gopkg.in/src-d/go-git.v4/utils/merkletrie"
)

// Commit represents a git commit
type Commit struct {
	content  string
	commit   *object.Commit
	filePath string
	repoName string
	sha      string
	message  string
	author   string
	email    string
	date     time.Time
}


// Leak represents a leaked secret or regex match.
type Leak struct {
	Line     string    `json:"line"`
	Commit   string    `json:"commit"`
	Offender string    `json:"offender"`
	Rule     string    `json:"rule"`
	Info     string    `json:"info"`
	Message  string    `json:"commitMsg"`
	Author   string    `json:"author"`
	Email    string    `json:"email"`
	File     string    `json:"file"`
	Repo     string    `json:"repo"`
	Date     time.Time `json:"date"`
	Tags     string    `json:"tags"`
	Severity string    `json:"severity"`
}

// Repo contains a src-d git repository and other data about the repo
type Repo struct {
	leaks         []Leak
	path          string
	url           string
	name          string
	repository    *git.Repository
	err           error
	auditDuration string
	numCommits    int64
}

func newRepo() (*Repo, error) {
	for _, re := range config.WhiteList.repos {
		if re.FindString(opts.Repo) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", opts.Repo)
		}
	}
	return &Repo{
		path: opts.RepoPath,
		url:  opts.Repo,
		name: filepath.Base(opts.Repo),
	}, nil
}

// clone will clone a repo
func (repo *Repo) clone() error {
	var (
		err        error
		repository *git.Repository
	)

	// check if cloning to disk
	if opts.Disk {
		log.Infof("cloning %s to disk", opts.Repo)
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if strings.HasPrefix(opts.Repo, "git") {
			// private
			repository, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
			})
		} else {
			// public
			options := &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			}
			if os.Getenv("GITHUB_TOKEN") != "" {
				options.Auth = &gitHttp.BasicAuth{
					Username: "fakeUsername", // yes, this can be anything except an empty string
					Password: os.Getenv("GITHUB_TOKEN"),
				}
			}
			repository, err = git.PlainClone(cloneTarget, false, options)
		}
	} else if repo.path != "" {
		log.Infof("opening %s", repo.path)
		repository, err = git.PlainOpen(repo.path)
		if err != nil {
			log.Errorf("unable to open %s", repo.path)
		}
	} else {
		// cloning to memory
		log.Infof("cloning %s", opts.Repo)
		if strings.HasPrefix(opts.Repo, "git") {
			repository, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
			})
		} else {
			options := &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			}
			if os.Getenv("GITHUB_TOKEN") != "" {
				options.Auth = &gitHttp.BasicAuth{
					Username: "fakeUsername", // yes, this can be anything except an empty string
					Password: os.Getenv("GITHUB_TOKEN"),
				}
			}
			repository, err = git.Clone(memory.NewStorage(), nil, options)
		}
	}
	repo.repository = repository
	repo.err = err
	return err
}

// audit performs an audit
func (repo *Repo) audit() error {
	var (
		err         error
		commitCount int64
		commitWg    sync.WaitGroup
		semaphore   chan bool
		logOpts     git.LogOptions
	)
	for _, re := range config.WhiteList.repos {
		if re.FindString(repo.name) != "" {
			return fmt.Errorf("skipping %s, whitelisted", repo.name)
		}
	}

	start := time.Now()

	// check if target contains an external gitleaks toml
	if opts.RepoConfig {
		err := config.updateFromRepo(repo)
		if err != nil {
			return err
		}
	}

	if opts.Commit != "" {
		h := plumbing.NewHash(opts.Commit)
		c, err := repo.repository.CommitObject(h)
		if err != nil {
			return err
		}

		totalCommits = totalCommits + 1
		repo.numCommits = 1
		return repo.auditSingleCommit(c)
	} else if opts.Branch != "" {
		refs, err := repo.repository.Storer.IterReferences()
		if err != nil {
			return err
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().IsTag() {
				return nil
			}
			// check heads first
			if ref.Name().String() == "refs/heads/"+opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			} else if ref.Name().String() == "refs/remotes/origin/"+opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			}
			return nil
		})
	} else {
		logOpts = git.LogOptions{
			All: true,
		}
	}

	// iterate all through commits
	cIter, err := repo.repository.Log(&logOpts)
	if err != nil {
		return err
	}

	if opts.Threads != 0 {
		threads = opts.Threads
	}
	if opts.RepoPath != "" {
		threads = 1
	}
	semaphore = make(chan bool, threads)

	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || (opts.Depth != 0 && commitCount == opts.Depth) {
			return storer.ErrStop
		}

		if config.WhiteList.commits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}

		// commits w/o parent (root of git the git ref)
		if len(c.ParentHashes) == 0 {
			commitCount = commitCount + 1
			totalCommits = totalCommits + 1
			err := repo.auditSingleCommit(c)
			if err != nil {
				return err
			}
			return nil
		}

		commitCount = commitCount + 1
		totalCommits = totalCommits + 1

		// regular commit audit
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

					for _, fr := range config.FileRules {
						for _, r := range fr.fileTypes {
							if r.FindString(filePath) != "" {
								commitInfo := &Commit{
									repoName: repo.name,
									filePath: filePath,
									sha:      c.Hash.String(),
									author:   c.Author.Name,
									email:    c.Author.Email,
									message:  strings.Replace(c.Message, "\n", " ", -1),
									date:     c.Author.When,
								}
								leak := *newLeak("N/A", fmt.Sprintf("filetype %s found", r.String()), r.String(), fr, commitInfo)
								mutex.Lock()
								repo.leaks = append(repo.leaks, leak)
								mutex.Unlock()
							}
						}
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
							diff := &Commit{
								repoName: repo.name,
								filePath: filePath,
								content:  chunk.Content(),
								sha:      c.Hash.String(),
								author:   c.Author.Name,
								email:    c.Author.Email,
								message:  strings.Replace(c.Message, "\n", " ", -1),
								date:     c.Author.When,
							}
							chunkLeaks := inspect(diff)
							for _, leak := range chunkLeaks {
								mutex.Lock()
								repo.leaks = append(repo.leaks, leak)
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
	repo.numCommits = commitCount
	repo.auditDuration = durafmt.Parse(time.Now().Sub(start)).String()

	return nil
}

func (repo *Repo) auditSingleCommit(c *object.Commit) error {
	fIter, err := c.Files()
	if err != nil {
		return err
	}

	// If current commit has parents then search for leaks in tree change,
	// that means scan in changed/modified files from one commit to another.
	if len(c.ParentHashes) > 0 {
		prevCommitObject, err := c.Parents().Next()
		if err != nil {
			return err
		}
		return repo.auditTreeChange(prevCommitObject, c)
	}

	// Scan for leaks in files related to current commit
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
		diff := &Commit{
			repoName: repo.name,
			filePath: f.Name,
			content:  content,
			sha:      c.Hash.String(),
			author:   c.Author.Name,
			email:    c.Author.Email,
			message:  strings.Replace(c.Message, "\n", " ", -1),
			date:     c.Author.When,
		}
		fileLeaks := inspect(diff)
		mutex.Lock()
		repo.leaks = append(repo.leaks, fileLeaks...)
		mutex.Unlock()
		return nil
	})
	return err
}

func (repo *Repo) report() {
	if len(repo.leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(repo.leaks), repo.numCommits, repo.auditDuration)
	} else {
		log.Infof("No leaks detected. %d commits inspected in %s", repo.numCommits, repo.auditDuration)
	}
}

// auditTreeChange will search for leaks in changed/modified files from one
// commit to another
func (repo *Repo) auditTreeChange(src, dst *object.Commit) error {
	var (
		skip bool
	)

	// Get state of src commit
	srcState, err := src.Tree()
	if err != nil {
		return err
	}

	// Get state of destination commit
	dstState, err := dst.Tree()
	if err != nil {
		return err
	}
	changes, err := srcState.Diff(dstState)

	// Run through each change
	for _, change := range changes {

		// Ignore deleted files
		action, err := change.Action()
		if err != nil {
			return err
		}
		if action == merkletrie.Delete {
			continue
		}

		// Get list of involved files
		_, to, err := change.Files()
		bin, err := to.IsBinary()
		if bin || err != nil {
			continue
		}

		for _, re := range config.WhiteList.files {
			if re.FindString(to.Name) != "" {
				log.Debugf("skipping whitelisted file (matched regex '%s'): %s", re.String(), to.Name)
				skip = true
			}
		}

		if skip {
			skip = false
			continue
		}

		content, err := to.Contents()
		if err != nil {
			return err
		}

		diff := &Commit{
			repoName: repo.name,
			filePath: to.Name,
			content:  content,
			sha:      dst.Hash.String(),
			author:   dst.Author.Name,
			email:    dst.Author.Email,
			message:  strings.Replace(dst.Message, "\n", " ", -1),
			date:     dst.Author.When,
		}
		fileLeaks := inspect(diff)
		mutex.Lock()
		repo.leaks = append(repo.leaks, fileLeaks...)
		mutex.Unlock()
	}
	return nil

}
