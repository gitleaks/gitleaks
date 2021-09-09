package scan

import (
	"github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
)

// CommitsScanner is a commit scanner
type CommitsScanner struct {
	opts options.Options
	cfg  config.Config

	repo     *git.Repository
	repoName string
	commits  []string
}

// NewCommitsScanner creates and returns a commits scanner, notice the 's' in commits
func NewCommitsScanner(opts options.Options, cfg config.Config, repo *git.Repository, commits []string) *CommitsScanner {
	return &CommitsScanner{
		opts:     opts,
		cfg:      cfg,
		repo:     repo,
		commits:  commits,
		repoName: getRepoName(opts),
	}
}

// Scan kicks off a CommitsScanner Scan
func (css *CommitsScanner) Scan() (Report, error) {
	var scannerReport Report
	for _, commitHash := range css.commits {
		c, err := obtainCommit(css.repo, commitHash)
		if err != nil {
			log.Errorf("skipping %s, err: %v", commitHash, err)
			continue
		}
		cs := NewCommitScanner(css.opts, css.cfg, css.repo, c)
		commitReport, err := cs.Scan()
		if err != nil {
			return scannerReport, err
		}
		scannerReport.Leaks = append(scannerReport.Leaks, commitReport.Leaks...)
		scannerReport.Commits++
	}
	return scannerReport, nil
}
