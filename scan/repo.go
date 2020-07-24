package scan

import (
	"context"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/zricethezav/gitleaks/v5/config"
	"github.com/zricethezav/gitleaks/v5/manager"

	"github.com/BurntSushi/toml"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	log "github.com/sirupsen/logrus"
)

// Repo wraps a *git.Repository object in addition to a manager object and the name of the repo.
// Commits are inspected from the *git.Repository object. If a Commit is found then we send it
// via the manager LeakChan where the manager receives and keeps track of all leaks.
type Repo struct {
	*git.Repository

	// config is used when the --repo-config option is set.
	// This allows users to load up configs specific to their repos.
	// Imagine the scenario where you are doing an scan of a large organization
	// and you want certain repos to look for specific rules. If those specific repos
	// have a gitleaks.toml or .gitleaks.toml config then those configs will be used specifically
	// for those repo scans.
	config config.Config

	// ctx is used to signal timeouts to running goroutines
	ctx    context.Context
	cancel context.CancelFunc

	Name    string
	Manager *manager.Manager
}

// NewRepo initializes and returns a Repo struct.
func NewRepo(m *manager.Manager) *Repo {
	return &Repo{
		Manager: m,
		config:  m.Config,
		ctx:     context.Background(),
	}
}

// Run accepts a manager and begins an scan based on the options/configs set in the manager.
func Run(m *manager.Manager) error {
	if m.Opts.OwnerPath != "" {
		files, err := ioutil.ReadDir(m.Opts.OwnerPath)
		if err != nil {
			return err
		}
		for _, f := range files {
			if !f.IsDir() {
				continue
			}
			m.Opts.RepoPath = fmt.Sprintf("%s/%s", m.Opts.OwnerPath, f.Name())
			if err := runHelper(NewRepo(m)); err != nil {
				log.Warnf("%s is not a git repo, skipping", f.Name())
			}
		}
		return nil
	}

	return runHelper(NewRepo(m))
}

func runHelper(r *Repo) error {
	// Ignore allowlisted repos
	for _, wlRepo := range r.Manager.Config.Allowlist.Repos {
		if RegexMatched(r.Manager.Opts.RepoPath, wlRepo) {
			return nil
		}
		if RegexMatched(r.Manager.Opts.Repo, wlRepo) {
			return nil
		}
	}
	if r.Manager.Opts.OpenLocal() {
		r.Name = path.Base(r.Manager.Opts.RepoPath)
		if err := r.Open(); err != nil {
			return err
		}

		// Check if we are checking uncommitted files. This is the default behavior
		// for a "$ gitleaks" command with no options set
		if r.Manager.Opts.CheckUncommitted() {
			if err := r.scanUncommitted(); err != nil {
				return err
			}
			return nil
		}
	} else {
		if err := r.Clone(nil); err != nil {
			return err
		}
	}
	return r.Scan()
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

// howManyThreads will return a number 1-GOMAXPROCS which is the number
// of goroutines that will spawn during gitleaks execution
func howManyThreads(threads int) int {
	maxThreads := runtime.GOMAXPROCS(0)
	if threads == 0 {
		return 1
	} else if threads > maxThreads {
		log.Warnf("%d threads set too high, setting to system max, %d", threads, maxThreads)
		return maxThreads
	}
	return threads
}

// getLogOptions determines what log options are used when iterating through commits.
// It is similar to `git log {branch}`. Default behavior is to log ALL branches so
// gitleaks gets the full git history.
func getLogOptions(repo *Repo) (*git.LogOptions, error) {
	var logOpts git.LogOptions
	const dateformat string = "2006-01-02"
	const timeformat string = "2006-01-02T15:04:05-0700"
	if repo.Manager.Opts.CommitFrom != "" {
		logOpts.From = plumbing.NewHash(repo.Manager.Opts.CommitFrom)
	}
	if repo.Manager.Opts.CommitSince != "" {
		if t, err := time.Parse(timeformat, repo.Manager.Opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else if t, err := time.Parse(dateformat, repo.Manager.Opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else {
			return nil, err
		}
	}
	if repo.Manager.Opts.CommitUntil != "" {
		if t, err := time.Parse(timeformat, repo.Manager.Opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else if t, err := time.Parse(dateformat, repo.Manager.Opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else {
			return nil, err
		}
	}
	if repo.Manager.Opts.Branch != "" {
		refs, err := repo.Storer.IterReferences()
		if err != nil {
			return nil, err
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().IsTag() {
				return nil
			}
			// check heads first
			if ref.Name().String() == "refs/heads/"+repo.Manager.Opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			} else if ref.Name().String() == "refs/remotes/origin/"+repo.Manager.Opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			}
			return nil
		})
		if logOpts.From.IsZero() {
			return nil, fmt.Errorf("could not find branch %s", repo.Manager.Opts.Branch)
		}
		return &logOpts, nil
	}
	if !logOpts.From.IsZero() || logOpts.Since != nil || logOpts.Until != nil {
		return &logOpts, nil
	}
	return &git.LogOptions{All: true}, nil
}

// howLong accepts a time.Time object which is subtracted from time.Now() and
// converted to nanoseconds which is returned
func howLong(t time.Time) int64 {
	return time.Now().Sub(t).Nanoseconds()
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

	repo.ctx, repo.cancel = context.WithTimeout(context.Background(), timeout)

	go func() {
		select {
		case <-repo.ctx.Done():
			if repo.timeoutReached() {
				log.Warnf("Timeout deadline (%s) exceeded for %s", timeout.String(), repo.Name)
			}
		}
	}()
	return nil
}
