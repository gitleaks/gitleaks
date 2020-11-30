package scan

import (
	"context"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"os"
	"time"

	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
)


type Scanner interface {
	Scan() ([]Leak, error)
}

type BaseScanner struct {
	opts options.Options
	cfg  config.Config

	ctx    context.Context
	cancel context.CancelFunc
	stopChan  chan os.Signal

	scannerType ScannerType
}

type ScannerType int

const (
	TypeRepoScanner ScannerType = iota +1
	TypeDirScanner
	TypeCommitScanner
	TypeCommitsScanner
	TypeUnstagedScanner
	TypeFilesAtCommitScanner
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
}

func NewScanner(opts options.Options, cfg config.Config) (Scanner, error) {
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
		ctx:  context.Background(),
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
	if opts.RepoConfig {
		base.cfg, err = loadRepoConfig(repo)
		if err != nil {
			return nil, err
		}
	}

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

func Report(leaks []Leak, opts options.Options) error {
	if len(leaks) != 0 {
		log.Warn("leaks found: ", len(leaks))
	} else {
		log.Info("leaks found: ", len(leaks))
	}
	if opts.Report != "" {
		file, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", " ")
		err = encoder.Encode(leaks)
		if err != nil {
			return err
		}
	}

	return nil
}
