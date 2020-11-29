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

func (css *CommitsScanner) Scan() ([]Leak, error) {
	for _, c := range css.commits {
		c, err := obtainCommit(css.repo, c)
		if err != nil {
			return css.leaks, nil
		}
		cs := NewCommitScanner(css.BaseScanner, css.repo, c)
		leaks, err := cs.Scan()
		if err != nil {
			return css.leaks, err
		}
		css.leaks = append(css.leaks, leaks...)
	}
	return css.leaks, nil
}
