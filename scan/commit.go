package scan

import (
	"fmt"
	"path/filepath"
	"strings"

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
func (cs *CommitScanner) Scan() (Report, error) {
	var scannerReport Report
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
					if cs.cfg.Allowlist.FileAllowed(filepath.Base(to.Path())) ||
						cs.cfg.Allowlist.PathAllowed(to.Path()) {
						continue
					}

					// Check individual file path ONLY rules
					for _, rule := range cs.cfg.Rules {
						if rule.CommitAllowListed(cs.commit.Hash.String()) {
							continue
						}

						if rule.HasFileOrPathLeakOnly(to.Path()) {
							leak := NewLeak("", "Filename or path offender: "+to.Path(), defaultLineNumber).WithCommit(cs.commit)
							leak.Repo = cs.repoName
							leak.File = to.Path()
							leak.RepoURL = cs.opts.RepoURL
							leak.LeakURL = leakURL(leak)
							leak.Rule = rule.Description
							leak.Tags = strings.Join(rule.Tags, ", ")

							if cs.opts.Verbose {
								leak.Log(cs.opts.Redact)
							}
							scannerReport.Leaks = append(scannerReport.Leaks, leak)
							continue
						}
					}

					lineLookup := make(map[string]bool)

					// Check the actual content
					for _, line := range strings.Split(chunk.Content(), "\n") {
						for _, rule := range cs.cfg.Rules {
							offender := rule.Inspect(line)
							if offender == "" || cs.cfg.Allowlist.RegexAllowed(offender) {
								continue
							}
							leak := NewLeak(line, offender, defaultLineNumber).WithCommit(cs.commit)
							if leak.Allowed(cs.cfg.Allowlist) {
								continue
							}
							leak.File = to.Path()
							leak.LineNumber = extractLine(patchContent, leak, lineLookup)
							leak.RepoURL = cs.opts.RepoURL
							leak.Repo = cs.repoName
							leak.LeakURL = leakURL(leak)
							leak.Rule = rule.Description
							leak.Tags = strings.Join(rule.Tags, ", ")
							if cs.opts.Verbose {
								leak.Log(cs.opts.Redact)
							}
							scannerReport.Leaks = append(scannerReport.Leaks, leak)
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
