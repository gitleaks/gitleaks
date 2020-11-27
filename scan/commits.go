package scan

import (
	"github.com/go-git/go-git/v5"
)

type CommitsScanner struct {
	BaseScanner

	repo    *git.Repository
	commits []string
	leaks   []Leak
}

func NewCommitsScanner(base BaseScanner, repo *git.Repository, commits []string) *CommitsScanner {
	return &CommitsScanner{
		BaseScanner: base,
		repo:        repo,
		commits:     commits,
	}
}

func (css *CommitsScanner) Scan() error {
	for _, c := range css.commits {
		c, err := obtainCommit(css.repo, c)
		if err != nil {
			return nil
		}
		cs := NewCommitScanner(css.BaseScanner, css.repo, c)
		if err := cs.Scan(); err != nil {
			return err
		}
		css.leaks = append(css.leaks, cs.GetLeaks()...)
	}
	return nil
}

func (css *CommitsScanner) GetLeaks() []Leak {
	return css.leaks
}
