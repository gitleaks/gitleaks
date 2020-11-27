package scan

import (
	"context"
	"github.com/zricethezav/gitleaks/v6/collector"
	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
	"sync"
	"time"
)

// Leak is a struct that contains information about some line of code that contains
// sensitive information as determined by the rules set in a gitleaks config
type Leak struct {
	Line       string    `json:"line"`
	LineNumber int       `json:"lineNumber"`
	Offender   string    `json:"offender"`
	Commit     string    `json:"commit"`
	Repo       string    `json:"repo"`
	Rule       string    `json:"rule"`
	Message    string    `json:"commitMessage"`
	Author     string    `json:"author"`
	Email      string    `json:"email"`
	File       string    `json:"file"`
	Date       time.Time `json:"date"`
	Tags       string    `json:"tags"`
	Operation  string    `json:"operation"`
	lookupHash string
}

type Scanner interface {
	Scan() error
	GetLeaks() []Leak
}

type BaseScanner struct {
	opts      options.Options
	cfg       config.Config

	// ctx is used to signal timeouts to running goroutines
	ctx    context.Context
	cancel context.CancelFunc

	leaks []Leak
}

func NewScanner(opts options.Options,  cfg config.Config) (Scanner, error) {
	for _, allowListedRepo := range cfg.Allowlist.Repos {
		if regexMatched(opts.RepoPath, allowListedRepo) {
			return nil, nil
		}
		if regexMatched(opts.Repo, allowListedRepo) {
			return nil, nil
		}
	}

	base := BaseScanner{
		opts:      opts,
		cfg:       cfg,
	}

	if opts.OwnerPath != "" {
		return NewDirScanner(base)
	}

	// get repo
	repo, err := getRepo(base.opts)
	if err != nil {
		return nil, err
	}

	// load up alternative config if possible, if not use manager's config
	if opts.RepoConfig {
		cfg, err = loadRepoConfig(repo)
		if err != nil {
			return nil, err
		}
	}

	if opts.Commit != "" {
		c, err := obtainCommit(repo, opts.Commit)
		if err != nil {
			return nil, err
		}
		return NewCommitScanner(base, repo, c), nil
	}
	if opts.Commits != "" || opts.CommitsFile != "" {
		return NewCommitsScanner(base)
	}
	if opts.FilesAtCommit != "" {
		// TODO
		c, err := obtainCommit(repo, opts.FilesAtCommit)
		if err != nil {
			return nil, err
		}
		return NewFilesAtCommitScanner(base, repo, c), nil
	}
	if opts.CheckUncommitted() {
		return NewUnstagedScanner(base, repo), nil
	}
	return NewRepoScanner(base, repo), nil
}

