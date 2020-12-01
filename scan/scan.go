package scan

import (
	"os"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/report"

	log "github.com/sirupsen/logrus"
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
)

// NewScanner accepts options and a config which will be used to determine and create a
// new scanner which is then returned.
func NewScanner(opts options.Options, cfg config.Config) (Scanner, error) {
	// TODO move this block to config parsing?
	for _, allowListedRepo := range cfg.Allowlist.Repos {
		if regexMatched(opts.RepoPath, allowListedRepo) {
			return nil, nil
		}
		if regexMatched(opts.Repo, allowListedRepo) {
			return nil, nil
		}
	}

	base := BaseScanner{
		opts: opts,
		cfg:  cfg,
	}

	// We want to return a dir scanner immediately since if the scan type is a directory scan
	// we don't want to clone/open a repo until inside DirScanner.Scan
	st := scanType(opts)
	if st == typeDirScanner {
		return NewDirScanner(base), nil
	}

	// Clone or open a repo
	repo, err := getRepo(base.opts)
	if err != nil {
		return nil, err
	}

	// load up alternative config if possible, if not use manager's config
	if opts.RepoConfig != "" {
		base.cfg, err = config.LoadRepoConfig(repo, opts.RepoConfig)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("starting scan on %s\n", getRepoName(opts))

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
	default:
		return NewRepoScanner(base, repo), nil
	}
}

func scanType(opts options.Options) ScannerType {
	if opts.OwnerPath != "" {
		return typeDirScanner
	}
	if opts.Commit != "" {
		return typeCommitScanner
	}
	if opts.Commits != "" || opts.CommitsFile != "" {
		return typeCommitsScanner
	}
	if opts.FilesAtCommit != "" {
		return typeFilesAtCommitScanner
	}
	if opts.CheckUncommitted() {
		return typeUnstagedScanner
	}
	return typeRepoScanner
}
