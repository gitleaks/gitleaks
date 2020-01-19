package audit

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/zricethezav/gitleaks/config"
	"github.com/zricethezav/gitleaks/manager"

	"github.com/BurntSushi/toml"
	"github.com/sergi/go-diff/diffmatchpatch"
	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-billy.v4"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/storer"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

// Repo wraps a *git.Repository object in addition to a manager object and the name of the repo.
// Commits are inspected from the *git.Repository object. If a commit is found then we send it
// via the manager LeakChan where the manager receives and keeps track of all leaks.
type Repo struct {
	*git.Repository

	// config is used when the --repo-config option is set.
	// This allows users to load up configs specific to their repos.
	// Imagine the scenario where you are doing an audit of a large organization
	// and you want certain repos to look for specific rules. If those specific repos
	// have a gitleaks.toml or .gitleaks.toml config then those configs will be used specifically
	// for those repo audits.
	config config.Config

	ctx context.Context

	Name    string
	Manager *manager.Manager
}

// NewRepo initializes and returns a Repo struct.
func NewRepo(m *manager.Manager) *Repo {
	return &Repo{
		Manager: m,
		config:  m.Config,
	}
}

// Clone will clone a repo and return a Repo struct which contains a go-git repo. The clone method
// is determined by the clone options set in Manager.metadata.cloneOptions
func (repo *Repo) Clone(cloneOption *git.CloneOptions) error {
	var (
		repository *git.Repository
		err        error
	)
	if cloneOption == nil {
		cloneOption = repo.Manager.CloneOptions
	}

	log.Infof("cloning... %s", cloneOption.URL)
	start := time.Now()

	if repo.Manager.CloneDir != "" {
		clonePath := fmt.Sprintf("%s/%x", repo.Manager.CloneDir, md5.Sum([]byte(time.Now().String())))
		repository, err = git.PlainClone(clonePath, false, cloneOption)
	} else {
		repository, err = git.Clone(memory.NewStorage(), nil, cloneOption)
	}
	if err != nil {
		return err
	}
	repo.Name = filepath.Base(repo.Manager.Opts.Repo)
	repo.Repository = repository
	repo.Manager.RecordTime(manager.CloneTime(howLong(start)))

	return nil
}

// AuditUncommitted will do a `git diff` and scan changed files that are being tracked. This is useful functionality
// for a pre-commit hook so you can make sure your code does not have any leaks before committing.
func (repo *Repo) AuditUncommitted() error {
	// load up alternative config if possible, if not use manager's config
	if repo.Manager.Opts.RepoConfig {
		cfg, err := repo.loadRepoConfig()
		if err != nil {
			return err
		}
		repo.config = cfg
	}

	auditTimeStart := time.Now()

	r, err := repo.Head()
	if err != nil {
		return err
	}

	c, err := repo.CommitObject(r.Hash())
	if err != nil {
		return err
	}
	// Staged change so the commit details do not yet exist. Insert empty defaults.
	c.Hash = plumbing.Hash{}
	c.Message = "***STAGED CHANGES***"
	c.Author.Name = ""
	c.Author.Email = ""
	c.Author.When = time.Unix(0, 0).UTC()

	prevTree, err := c.Tree()
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	status, err := wt.Status()
	for fn, state := range status {
		var (
			prevFileContents string
			currFileContents string
			filename         string
		)

		if state.Staging != git.Untracked {
			if state.Staging == git.Deleted {
				// file in staging has been deleted, aka it is not on the filesystem
				// so the contents of the file are ""
				currFileContents = ""
			} else {
				workTreeBuf := bytes.NewBuffer(nil)
				workTreeFile, err := wt.Filesystem.Open(fn)
				if err != nil {
					continue
				}
				if _, err := io.Copy(workTreeBuf, workTreeFile); err != nil {
					return err
				}
				currFileContents = workTreeBuf.String()
				filename = workTreeFile.Name()
			}

			// get files at HEAD state
			prevFile, err := prevTree.File(fn)
			if err != nil {
				prevFileContents = ""

			} else {
				prevFileContents, err = prevFile.Contents()
				if err != nil {
					return err
				}
				if filename == "" {
					filename = prevFile.Name
				}
			}

			if fileMatched(filename, repo.config.Whitelist.File) {
				log.Debugf("whitelisted file found, skipping audit of file: %s", filename)
			} else if fileMatched(filename, repo.config.FileRegex) {
				repo.Manager.SendLeaks(manager.Leak{
					Line:     "N/A",
					Offender: filename,
					Commit:   c.Hash.String(),
					Repo:     repo.Name,
					Rule:     "file regex matched" + repo.config.FileRegex.String(),
					Message:  c.Message,
					Author:   c.Author.Name,
					Email:    c.Author.Email,
					Date:     c.Author.When,
					File:     filename,
				})
			} else {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(prevFileContents, currFileContents, false)
				var diffContents string
				for _, d := range diffs {
					switch d.Type {
					case diffmatchpatch.DiffInsert:
						diffContents += fmt.Sprintf("%s\n", d.Text)
					case diffmatchpatch.DiffDelete:
						diffContents += fmt.Sprintf("%s\n", d.Text)
					}
				}
				InspectString(diffContents, c, repo, filename)
			}
		}
	}

	if err != nil {
		return err
	}
	repo.Manager.RecordTime(manager.AuditTime(howLong(auditTimeStart)))
	return nil
}

// timeoutReached returns true if the timeout deadline has been met. This function should be used
// at the top of loops and before potentially long running goroutines (like checking inefficient regexes)
func (repo *Repo) timeoutReached() bool {
	if repo.ctx.Err() == context.DeadlineExceeded {
		return true
	}
	return false
}

// setupTimeout parses the --timeout option and assigns a context with timeout to the manager
// which will exit early if the timeout has been met.
func (repo *Repo) setupTimeout() error {
	if repo.Manager.Opts.Timeout == "" {
		return nil
	}
	timeout, err := time.ParseDuration(repo.Manager.Opts.Timeout)
	if err != nil {
		return err
	}

	repo.ctx, _ = context.WithTimeout(context.Background(), timeout)

	go func() {
		select {
		case <-repo.ctx.Done():
			log.Warnf("Timeout deadline exceeded: %s", timeout.String())
		}
	}()
	return nil
}

// Audit is responsible for scanning the entire history (default behavior) of a
// git repo. Options that can change the behavior of this function include: --commit, --depth, --branch.
// See options/options.go for an explanation on these options.
func (repo *Repo) Audit() error {
	if err := repo.setupTimeout(); err != nil {
		return err
	}

	if repo.Repository == nil {
		return fmt.Errorf("%s repo is empty", repo.Name)
	}

	// load up alternative config if possible, if not use manager's config
	if repo.Manager.Opts.RepoConfig {
		cfg, err := repo.loadRepoConfig()
		if err != nil {
			return err
		}
		repo.config = cfg
	}

	auditTimeStart := time.Now()

	// audit single Commit
	if repo.Manager.Opts.Commit != "" {
		h := plumbing.NewHash(repo.Manager.Opts.Commit)
		c, err := repo.CommitObject(h)
		if err != nil {
			return err
		}

		err = inspectCommit(c, repo)
		if err != nil {
			return err
		}
		return nil
	}

	logOpts, err := getLogOptions(repo)
	if err != nil {
		return err
	}
	cIter, err := repo.Log(logOpts)
	if err != nil {
		return err
	}

	cc := 0
	semaphore := make(chan bool, howManyThreads(repo.Manager.Opts.Threads))
	wg := sync.WaitGroup{}
	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || c.Hash.String() == repo.Manager.Opts.CommitTo || repo.timeoutReached() {
			return storer.ErrStop
		}

		if len(c.ParentHashes) == 0 {
			cc++
			err = inspectCommit(c, repo)
			if err != nil {
				return err
			}
			return nil
		}

		if isCommitWhiteListed(c.Hash.String(), repo.config.Whitelist.Commits) {
			return nil
		}

		cc++
		err = c.Parents().ForEach(func(parent *object.Commit) error {
			defer func() {
				if err := recover(); err != nil {
					// sometimes the patch generation will fail due to a known bug in
					// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
					// Once a fix has been merged I will remove this recover.
					return
				}
			}()
			if repo.timeoutReached() {
				return nil
			}
			start := time.Now()
			patch, err := c.Patch(parent)
			if err != nil {
				return fmt.Errorf("could not generate patch")
			}
			repo.Manager.RecordTime(manager.PatchTime(howLong(start)))
			wg.Add(1)
			semaphore <- true
			go func(c *object.Commit, patch *object.Patch) {
				defer func() {
					<-semaphore
					wg.Done()
				}()
				inspectPatch(patch, c, repo)
			}(c, patch)

			return nil
		})
		return nil
	})

	wg.Wait()
	repo.Manager.RecordTime(manager.AuditTime(howLong(auditTimeStart)))
	repo.Manager.IncrementCommits(cc)
	return nil
}

// Open opens a local repo either from repo-path or $PWD
func (repo *Repo) Open() error {
	if repo.Manager.Opts.RepoPath != "" {
		// open git repo from repo path
		repository, err := git.PlainOpen(repo.Manager.Opts.RepoPath)
		if err != nil {
			return err
		}
		repo.Repository = repository
	} else {
		// open git repo from PWD
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		repository, err := git.PlainOpen(dir)
		if err != nil {
			return err
		}
		repo.Repository = repository
		repo.Name = path.Base(dir)
	}
	return nil
}

func (repo *Repo) loadRepoConfig() (config.Config, error) {
	wt, err := repo.Repository.Worktree()
	if err != nil {
		return config.Config{}, err
	}
	var f billy.File
	f, _ = wt.Filesystem.Open(".gitleaks.toml")
	if f == nil {
		f, err = wt.Filesystem.Open("gitleaks.toml")
		if err != nil {
			return config.Config{}, fmt.Errorf("problem loading repo config: %v", err)
		}
	}
	defer f.Close()
	var tomlLoader config.TomlLoader
	_, err = toml.DecodeReader(f, &tomlLoader)
	return tomlLoader.Parse()
}
