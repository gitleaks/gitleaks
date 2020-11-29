package scan

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type FilesAtCommitScanner struct {
	BaseScanner
	repo   *git.Repository
	commit *object.Commit
	leaks []Leak
}

func NewFilesAtCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *FilesAtCommitScanner {
	fs := &FilesAtCommitScanner{
		BaseScanner: base,
		repo:   repo,
		commit: commit,
	}
	fs.scannerType = TypeFilesAtCommitScanner
	return fs
}

func (fs *FilesAtCommitScanner) Scan() ([]Leak, error) {
	fIter, err := fs.commit.Files()
	if err != nil {
		return fs.leaks, err
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

		fs.leaks = append(fs.leaks, checkRules(fs.BaseScanner, fs.commit, "", f.Name, content)...)
		return nil
	})

	return fs.leaks, err
}
