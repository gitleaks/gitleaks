package scan

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/report"
)

// Scanner abstracts unique scanner internals while exposing the Scan function which
// returns a report.
type Scanner interface {
	Scan() (report.Report, error)
}

// BaseScanner is a container for common data each scanner needs.
type BaseScanner struct {
	opts        options.Options
	cfg         config.Config
	stopChan    chan os.Signal
	scannerType ScannerType
}

// ScannerType is the scanner type which is determined based on program arguments
type ScannerType int

const (
	typeRepoScanner ScannerType = iota + 1
	typeDirScanner
	typeCommitScanner
	typeCommitsScanner
	typeUnstagedScanner
	typeFilesAtCommitScanner
	typeNoGitScanner
	typeEmpty
)

// NewScanner accepts options and a config which will be used to determine and create a
// new scanner which is then returned.
func NewScanner(opts options.Options, cfg config.Config) (Scanner, error) {
	var (
		repo *git.Repository
		err  error
	)
	// TODO move this block to config parsing?
	for _, allowListedRepo := range cfg.Allowlist.Repos {
		if regexMatched(opts.Path, allowListedRepo) {
			return nil, nil
		}
		if regexMatched(opts.RepoURL, allowListedRepo) {
			return nil, nil
		}
	}
	base := BaseScanner{
		opts: opts,
		cfg:  cfg,
	}

	// We want to return a dir scanner immediately since if the scan type is a directory scan
	// we don't want to clone/open a repo until inside ParentScanner.Scan
	st, err := scanType(opts)
	if err != nil {
		return nil, err
	}
	if st == typeDirScanner {
		return NewParentScanner(base), nil
	}

	// Clone or open a repo if we need it
	if needsRepo(st) {
		repo, err = getRepo(base.opts)
		if err != nil {
			return nil, err
		}
	}

	// load up alternative config if possible, if not use manager's config
	if opts.RepoConfigPath != "" {
		base.cfg, err = config.LoadRepoConfig(repo, opts.RepoConfigPath)
		if err != nil {
			return nil, err
		}
	}

	switch st {
	case typeCommitScanner:
		c, err := obtainCommit(repo, opts.Commit)
		if err != nil {
			return nil, err
		}
		return NewCommitScanner(base, repo, c), nil
	case typeCommitsScanner:
		commits, err := optsToCommits(opts)
		if err != nil {
			return nil, err
		}
		return NewCommitsScanner(base, repo, commits), nil
	case typeFilesAtCommitScanner:
		c, err := obtainCommit(repo, opts.FilesAtCommit)
		if err != nil {
			return nil, err
		}
		return NewFilesAtCommitScanner(base, repo, c), nil
	case typeUnstagedScanner:
		return NewUnstagedScanner(base, repo), nil
	case typeDirScanner:
		return NewParentScanner(base), nil
	case typeNoGitScanner:
		return NewNoGitScanner(base), nil
	default:
		return NewRepoScanner(base, repo), nil
	}
}

func scanType(opts options.Options) (ScannerType, error) {
	//if opts.OwnerPath != "" {
	//	return typeDirScanner
	//}
	if opts.Commit != "" {
		return typeCommitScanner, nil
	}
	if opts.Commits != "" || opts.CommitsFile != "" {
		return typeCommitsScanner, nil
	}
	if opts.FilesAtCommit != "" {
		return typeFilesAtCommitScanner, nil
	}
	if opts.Path != "" && !opts.NoGit {
		if opts.CheckUncommitted() {
			return typeUnstagedScanner, nil
		}
		_, err := os.Stat(filepath.Join(opts.Path))
		if err != nil {
			return typeEmpty, err
		}
		// check if path/.git exists, if it does, this is a repo scan
		// if not this is a multi-repo scan
		_, err = os.Stat(filepath.Join(opts.Path, ".git"))
		if os.IsNotExist(err) {
			return typeDirScanner, nil
		}
		return typeRepoScanner, nil
	}
	if opts.Path != "" && opts.NoGit {
		_, err := os.Stat(filepath.Join(opts.Path))
		if err != nil {
			return typeEmpty, err
		}
		return typeNoGitScanner, nil
	}
	if opts.CheckUncommitted() {
		return typeUnstagedScanner, nil
	}

	// default to the most commonly used scanner, RepoScanner
	return typeRepoScanner, nil
}

func needsRepo(st ScannerType) bool {
	if !(st == typeDirScanner || st == typeNoGitScanner) {
		return true
	}
	return false
}
