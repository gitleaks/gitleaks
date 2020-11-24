package scan

import (
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/zricethezav/gitleaks/v6/repo"
)

type CommitsScanner struct {
	repo      *repo.Repo
	commit *object.Commit
}

func NewCommitsScanner(commits []string, repo *repo.Repo) (*CommitScanner, error) {
	return &CommitScanner{
		repo:   nil,
		commit: nil,
	}, nil
}

func (c *CommitsScanner) Scan() error {
	return nil
}
