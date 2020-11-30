package scan

import (
	"github.com/go-git/go-git/v5"
)

type CommitsScanner struct {
	BaseScanner

	repo     *git.Repository
	repoName string
	commits  []string
}

func NewCommitsScanner(base BaseScanner, repo *git.Repository, commits []string) *CommitsScanner {
	return &CommitsScanner{
		BaseScanner: base,
		repo:        repo,
		commits:     commits,
		repoName:    getRepoName(base.opts),
	}
}

func (css *CommitsScanner) Scan() (Report, error) {
	var report Report
	for _, c := range css.commits {
		c, err := obtainCommit(css.repo, c)
		if err != nil {
			return report, nil
		}
		cs := NewCommitScanner(css.BaseScanner, css.repo, c)
		commitReport, err := cs.Scan()
		if err != nil {
			return report, err
		}
		report.Leaks = append(report.Leaks, commitReport.Leaks...)
		report.Commits++
	}
	return report, nil
}
