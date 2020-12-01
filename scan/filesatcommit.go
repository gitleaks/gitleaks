package scan

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/zricethezav/gitleaks/v7/report"
)

type FilesAtCommitScanner struct {
	BaseScanner

	repo     *git.Repository
	commit   *object.Commit
	repoName string
}

func NewFilesAtCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *FilesAtCommitScanner {
	fs := &FilesAtCommitScanner{
		BaseScanner: base,
		repo:        repo,
		commit:      commit,
		repoName:    getRepoName(base.opts),
	}
	fs.scannerType = TypeFilesAtCommitScanner
	return fs
}

func (fs *FilesAtCommitScanner) Scan() (report.Report, error) {
	var scannerReport report.Report
	fIter, err := fs.commit.Files()
	if err != nil {
		return scannerReport, err
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

		scannerReport.Leaks = append(scannerReport.Leaks, checkRules(fs.BaseScanner, fs.commit, fs.repoName, f.Name, content)...)
		return nil
	})

	scannerReport.Commits = 1
	return scannerReport, err
}
