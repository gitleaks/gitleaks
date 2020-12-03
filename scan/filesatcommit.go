package scan

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/zricethezav/gitleaks/v7/report"
)

// FilesAtCommitScanner is a files at commit scanner. This differs from CommitScanner
// as CommitScanner generates patches that are scanned. FilesAtCommitScanner instead looks at
// files available at a commit's worktree and scans the entire content of said files.
// Apologies for the awful struct name...
type FilesAtCommitScanner struct {
	BaseScanner

	repo     *git.Repository
	commit   *object.Commit
	repoName string
}

// NewFilesAtCommitScanner creates and returns a files at commit scanner
func NewFilesAtCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *FilesAtCommitScanner {
	fs := &FilesAtCommitScanner{
		BaseScanner: base,
		repo:        repo,
		commit:      commit,
		repoName:    getRepoName(base.opts),
	}
	fs.scannerType = typeFilesAtCommitScanner
	return fs
}

// Scan kicks off a FilesAtCommitScanner Scan
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
