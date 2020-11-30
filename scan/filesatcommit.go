package scan

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type FilesAtCommitScanner struct {
	BaseScanner

	repo   *git.Repository
	commit *object.Commit
	repoName string
}

func NewFilesAtCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *FilesAtCommitScanner {
	fs := &FilesAtCommitScanner{
		BaseScanner: base,
		repo:   repo,
		commit: commit,
		repoName: getRepoName(base.opts),
	}
	fs.scannerType = TypeFilesAtCommitScanner
	return fs
}

func (fs *FilesAtCommitScanner) Scan() (Report, error) {
	var report Report
	fIter, err := fs.commit.Files()
	if err != nil {
		return report, err
	}

	err = fIter.ForEach(func(f *object.File) error {
		bin, err := f.IsBinary()
		if bin {
			return nil
		} else if err != nil {
			return err
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}

		report.Leaks = append(report.Leaks, checkRules(fs.BaseScanner, fs.commit, fs.repoName, f.Name, content)...)
		return nil
	})

	report.Commits = 1
	return report, err
}
