package scan

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
)

// Scanner abstracts unique scanner internals while exposing the Scan function which
// returns a report.
type Scanner interface {
	Scan() (Report, error)
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

	// We want to return a dir scanner immediately since if the scan type is a directory scan
	// we don't want to clone/open a repo until inside ParentScanner.Scan
	st, err := scanType(opts)
	if err != nil {
		return nil, err
	}
	if st == typeDirScanner {
		if opts.AdditionalConfig != "" {
			additionalCfg, err := config.LoadAdditionalConfig(opts.AdditionalConfig)
			if err != nil {
				return nil, err
			}
			cfg = cfg.AppendConfig(additionalCfg)
		}
		return NewParentScanner(opts, cfg), nil
	}

	// Clone or open a repo if we need it
	if needsRepo(st) {
		repo, err = getRepo(opts)
		if err != nil {
			return nil, err
		}
	}

	// load up alternative config if possible, if not use default/specified config. Will append if AppendRepoConfig is true
	if opts.RepoConfigPath != "" && !opts.NoGit {
		repoCfg, err := config.LoadRepoConfig(repo, opts.RepoConfigPath)
		if err != nil {
			return nil, err
		}
		if opts.AppendRepoConfig {
			cfg = cfg.AppendConfig(repoCfg)
		} else {
			cfg = repoCfg
		}
	}

	// append additional config with the rest of the config
	if opts.AdditionalConfig != "" {
		additionalCfg, err := config.LoadAdditionalConfig(opts.AdditionalConfig)
		if err != nil {
			return nil, err
		}
		cfg = cfg.AppendConfig(additionalCfg)
	}

	switch st {
	case typeCommitScanner:
		c, err := obtainCommit(repo, opts.Commit)
		if err != nil {
			return nil, err
		}
		return NewCommitScanner(opts, cfg, repo, c), nil
	case typeCommitsScanner:
		commits, err := optsToCommits(opts)
		if err != nil {
			return nil, err
		}
		return NewCommitsScanner(opts, cfg, repo, commits), nil
	case typeFilesAtCommitScanner:
		c, err := obtainCommit(repo, opts.FilesAtCommit)
		if err != nil {
			return nil, err
		}
		return NewFilesAtCommitScanner(opts, cfg, repo, c), nil
	case typeUnstagedScanner:
		return NewUnstagedScanner(opts, cfg, repo), nil
	case typeDirScanner:
		return NewParentScanner(opts, cfg), nil
	case typeNoGitScanner:
		return NewNoGitScanner(opts, cfg), nil
	default:
		return NewRepoScanner(opts, cfg, repo), nil
	}
}

func scanType(opts options.Options) (ScannerType, error) {
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
