package scan

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v7/report"

	"github.com/go-git/go-git/v5"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CommitScanner is a commit scanner
type CommitScanner struct {
	BaseScanner
	repo     *git.Repository
	repoName string
	commit   *object.Commit
}

// NewCommitScanner creates and returns a commit scanner
func NewCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *CommitScanner {
	cs := &CommitScanner{
		BaseScanner: base,
		repo:        repo,
		commit:      commit,
		repoName:    getRepoName(base.opts),
	}
	cs.scannerType = typeCommitScanner
	return cs
}

// Scan kicks off a CommitScanner Scan
func (cs *CommitScanner) Scan() (report.Report, error) {
	var scannerReport report.Report
	if len(cs.commit.ParentHashes) == 0 {
		facScanner := NewFilesAtCommitScanner(cs.BaseScanner, cs.repo, cs.commit)
		return facScanner.Scan()
	}

	err := cs.commit.Parents().ForEach(func(parent *object.Commit) error {
		defer func() {
			if err := recover(); err != nil {
				// sometimes the Patch generation will fail due to a known bug in
				// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
				// Once a fix has been merged I will remove this recover.
				return
			}
		}()
		if parent == nil {
			return nil
		}

		patch, err := parent.Patch(cs.commit)
		if err != nil {
			return fmt.Errorf("could not generate Patch")
		}

		patchContent := patch.String()

		for _, f := range patch.FilePatches() {
			if f.IsBinary() {
				continue
			}
			for _, chunk := range f.Chunks() {
				if chunk.Type() == fdiff.Add {
					_, to := f.Files()
					leaks := checkRules(cs.BaseScanner, cs.commit, cs.repoName, to.Path(), chunk.Content())

					lineLookup := make(map[string]bool)
					for _, leak := range leaks {
						leak.LineNumber = extractLine(patchContent, leak, lineLookup)
						leak.LeakURL = leakURL(leak)
						scannerReport.Leaks = append(scannerReport.Leaks, leak)
						if cs.opts.Verbose {
							logLeak(leak, cs.opts.Redact)
						}
					}
				}
			}
		}
		return nil
	})
	scannerReport.Commits = 1
	return scannerReport, err
}
