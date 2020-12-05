package scan

import (
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
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
func (fs *FilesAtCommitScanner) Scan() (Report, error) {
	var scannerReport Report
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

		// Check individual file path ONLY rules
		for _, rule := range fs.cfg.Rules {
			if rule.CommitAllowed(fs.commit.Hash.String()) {
				continue
			}

			if rule.HasFileOrPathLeakOnly(f.Name) {
				leak := NewLeak("", "Filename or path offender: "+f.Name, defaultLineNumber).WithCommit(fs.commit)
				leak.Repo = fs.repoName
				leak.File = f.Name
				leak.RepoURL = fs.opts.RepoURL
				leak.LeakURL = leakURL(leak)
				leak.Rule = rule.Description
				leak.Tags = strings.Join(rule.Tags, ", ")

				if fs.opts.Verbose {
					leak.Log(fs.opts.Redact)
				}
				scannerReport.Leaks = append(scannerReport.Leaks, leak)
				continue
			}
		}

		for i, line := range strings.Split(content, "\n") {
			for _, rule := range fs.cfg.Rules {
				offender := rule.Inspect(line)

				if offender == "" {
					continue
				}
				if fs.cfg.Allowlist.RegexAllowed(line) ||
					rule.AllowList.FileAllowed(filepath.Base(f.Name)) ||
					rule.AllowList.PathAllowed(f.Name) ||
					rule.AllowList.CommitAllowed(fs.commit.Hash.String()) {
					continue
				}

				if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(f.Name)) {
					continue
				}
				if rule.Path.String() != "" && !rule.HasFilePathLeak(f.Name) {
					continue
				}

				leak := NewLeak(line, offender, defaultLineNumber).WithCommit(fs.commit)
				leak.File = f.Name
				leak.LineNumber = i + 1
				leak.RepoURL = fs.opts.RepoURL
				leak.Repo = fs.repoName
				leak.LeakURL = leakURL(leak)
				leak.Rule = rule.Description
				leak.Tags = strings.Join(rule.Tags, ", ")
				if fs.opts.Verbose {
					leak.Log(fs.opts.Redact)
				}
				scannerReport.Leaks = append(scannerReport.Leaks, leak)
			}
		}

		return nil
	})

	scannerReport.Commits = 1
	return scannerReport, err
}
