package scan

import (
	"os"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/report"

	log "github.com/sirupsen/logrus"
)

type Scanner interface {
	Scan() (report.Report, error)
}

type BaseScanner struct {
	opts        options.Options
	cfg         config.Config
	stopChan    chan os.Signal
	scannerType ScannerType
}

type ScannerType int

const (
	TypeRepoScanner ScannerType = iota + 1
	TypeDirScanner
	TypeCommitScanner
	TypeCommitsScanner
	TypeUnstagedScanner
	TypeFilesAtCommitScanner
)

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
	if st == TypeDirScanner {
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
	case TypeCommitScanner:
		c, err := obtainCommit(repo, opts.Commit)
		if err != nil {
			return nil, err
		}
		return NewCommitScanner(base, repo, c), nil
	case TypeCommitsScanner:
		commits, err := optsToCommits(opts)
		if err != nil {
			return nil, err
		}
		return NewCommitsScanner(base, repo, commits), nil
	case TypeFilesAtCommitScanner:
		c, err := obtainCommit(repo, opts.FilesAtCommit)
		if err != nil {
			return nil, err
		}
		return NewFilesAtCommitScanner(base, repo, c), nil
	case TypeUnstagedScanner:
		return NewUnstagedScanner(base, repo), nil
	default:
		return NewRepoScanner(base, repo), nil
	}
}

func scanType(opts options.Options) ScannerType {
	if opts.OwnerPath != "" {
		return TypeDirScanner
	}
	if opts.Commit != "" {
		return TypeCommitScanner
	}
	if opts.Commits != "" || opts.CommitsFile != "" {
		return TypeCommitsScanner
	}
	if opts.FilesAtCommit != "" {
		return TypeFilesAtCommitScanner
	}
	if opts.CheckUncommitted() {
		return TypeUnstagedScanner
	}
	return TypeRepoScanner
}
