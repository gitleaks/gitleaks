package scan

import (
	"github.com/go-git/go-git/v5"
)

// CommitsScanner is a commit scanner
type CommitsScanner struct {
	BaseScanner

	repo     *git.Repository
	repoName string
	commits  []string
}

// NewCommitsScanner creates and returns a commits scanner, notice the 's' in commits
func NewCommitsScanner(base BaseScanner, repo *git.Repository, commits []string) *CommitsScanner {
	return &CommitsScanner{
		BaseScanner: base,
		repo:        repo,
		commits:     commits,
		repoName:    getRepoName(base.opts),
	}
}

// Scan kicks off a CommitsScanner Scan
func (css *CommitsScanner) Scan() (Report, error) {
	var scannerReport Report
	for _, c := range css.commits {
		c, err := obtainCommit(css.repo, c)
		if err != nil {
			return scannerReport, nil
		}
		cs := NewCommitScanner(css.BaseScanner, css.repo, c)
		commitReport, err := cs.Scan()
		if err != nil {
			return scannerReport, err
		}
		scannerReport.Leaks = append(scannerReport.Leaks, commitReport.Leaks...)
		scannerReport.Commits++
	}
	return scannerReport, nil
}
