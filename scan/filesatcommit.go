package scan

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type FilesAtCommitScanner struct {
	BaseScanner
	repo   *git.Repository
	commit *object.Commit
}

func NewFilesAtCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *FilesAtCommitScanner {
	return &FilesAtCommitScanner{
		BaseScanner: base,
		repo:   repo,
		commit: commit,
	}
}

func (fs *FilesAtCommitScanner) Scan() error {
	fIter, err := fs.commit.Files()
	if err != nil {
		return err
	}

	err = fIter.ForEach(func(f *object.File) error {
		bin, err := f.IsBinary()
		if bin || timeoutReached(fs.ctx) {
			return nil
		} else if err != nil {
			return err
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}

		checkRules(fs.cfg, "", f.Name, fs.commit, content)
		return nil
	})

	return nil
}

func (fs *FilesAtCommitScanner) GetLeaks() []Leak {
	return fs.leaks
}
