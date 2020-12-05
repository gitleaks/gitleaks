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
	patch    *object.Patch
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

// SetRepoName sets the repo name of the scanner.
func (cs *CommitScanner) SetRepoName(repoName string) {
	cs.repoName = repoName
}

// SetPatch sets the patch to be inspected by the commit scanner. This is used to avoid
// a race condition when running a threaded repo scan
func (cs *CommitScanner) SetPatch(patch *object.Patch) {
	cs.patch = patch
}

// Scan kicks off a CommitScanner Scan
func (cs *CommitScanner) Scan() (Report, error) {
	var scannerReport Report
	if len(cs.commit.ParentHashes) == 0 {
		facScanner := NewFilesAtCommitScanner(cs.BaseScanner, cs.repo, cs.commit)
		return facScanner.Scan()
	}

	if cs.patch == nil {
		parent, err := cs.commit.Parent(0)
		if err != nil {
			return scannerReport, err
		}

		if parent == nil {
			return scannerReport, nil
		}

		cs.patch, err = parent.Patch(cs.commit)
		if err != nil {
			return scannerReport, fmt.Errorf("could not generate Patch")
		}
	}

	patchContent := cs.patch.String()

	for _, f := range cs.patch.FilePatches() {
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
					if rule.CommitAllowed(cs.commit.Hash.String()) {
						continue
					}

					if rule.HasFileOrPathLeakOnly(to.Path()) {
						leak := NewLeak("", "Filename or path offender: "+to.Path(), defaultLineNumber).WithCommit(cs.commit)
						leak.Repo = cs.repoName
						leak.File = to.Path()
						leak.RepoURL = cs.opts.RepoURL
						leak.LeakURL = leak.URL()
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
						if offender == "" {
							continue
						}
						if cs.cfg.Allowlist.RegexAllowed(line) ||
							rule.AllowList.FileAllowed(filepath.Base(to.Path())) ||
							rule.AllowList.PathAllowed(to.Path()) ||
							rule.AllowList.CommitAllowed(cs.commit.Hash.String()) {
							continue
						}

						if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(to.Path())) {
							continue
						}
						if rule.Path.String() != "" && !rule.HasFilePathLeak(to.Path()) {
							continue
						}

						leak := NewLeak(line, offender, defaultLineNumber).WithCommit(cs.commit)
						leak.File = to.Path()
						leak.LineNumber = extractLine(patchContent, leak, lineLookup)
						leak.RepoURL = cs.opts.RepoURL
						leak.Repo = cs.repoName
						leak.LeakURL = leak.URL()
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
	scannerReport.Commits = 1
	return scannerReport, nil
}
