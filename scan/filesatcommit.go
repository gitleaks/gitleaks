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

		fs.leaks = checkRules(fs.cfg, "", f.Name, fs.commit, content)
		for _, leak := range fs.leaks {
			logLeak(leak)
		}
		return nil
	})

	return fs.leaks, err
}
