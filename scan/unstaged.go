package scan

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// UnstagedScanner is an unstaged scanner. This is the scanner used when you don't provide program arguments
// which will then scan your PWD. This scans unstaged changes in your repo.
type UnstagedScanner struct {
	BaseScanner
	repo     *git.Repository
	repoName string
}

// NewUnstagedScanner returns an unstaged scanner
func NewUnstagedScanner(base BaseScanner, repo *git.Repository) *UnstagedScanner {
	us := &UnstagedScanner{
		BaseScanner: base,
		repo:        repo,
		repoName:    getRepoName(base.opts),
	}
	us.scannerType = typeUnstagedScanner
	return us
}

// Scan kicks off an unstaged scan. This will attempt to determine unstaged changes which are then scanned.
func (us *UnstagedScanner) Scan() (Report, error) {
	var scannerReport Report
	r, err := us.repo.Head()
	if err == plumbing.ErrReferenceNotFound {
		wt, err := us.repo.Worktree()
		if err != nil {
			return scannerReport, err
		}

		status, err := wt.Status()
		if err != nil {
			return scannerReport, err
		}
		for fn := range status {
			workTreeBuf := bytes.NewBuffer(nil)
			workTreeFile, err := wt.Filesystem.Open(fn)
			if err != nil {
				continue
			}
			if _, err := io.Copy(workTreeBuf, workTreeFile); err != nil {
				return scannerReport, err
			}
			lineNumber := 0
			for _, line := range strings.Split(workTreeBuf.String(), "\n") {
				lineNumber++
				for _, rule := range us.cfg.Rules {
					offender := rule.Inspect(line)
					if offender == "" {
						continue
					}
					if us.cfg.Allowlist.RegexAllowed(line) ||
						rule.AllowList.FileAllowed(filepath.Base(workTreeFile.Name())) ||
						rule.AllowList.PathAllowed(workTreeFile.Name()) {
						continue
					}
					if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(workTreeFile.Name())) {
						continue
					}
					if rule.Path.String() != "" && !rule.HasFilePathLeak(filepath.Base(workTreeFile.Name())) {
						continue
					}
					leak := NewLeak(line, offender, defaultLineNumber).WithCommit(emptyCommit())
					leak.File = workTreeFile.Name()
					leak.LineNumber = lineNumber
					leak.Repo = us.repoName
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")
					if us.opts.Verbose {
						leak.Log(us.opts.Redact)
					}
					scannerReport.Leaks = append(scannerReport.Leaks, leak)
				}
			}
		}
		return scannerReport, nil
	} else if err != nil {
		return scannerReport, err
	}

	c, err := us.repo.CommitObject(r.Hash())
	if err != nil {
		return scannerReport, err
	}

	// Staged change so the Commit details do not yet exist. Insert empty defaults.
	c.Hash = plumbing.Hash{}
	c.Message = ""
	c.Author.Name = ""
	c.Author.Email = ""
	c.Author.When = time.Unix(0, 0).UTC()

	prevTree, err := c.Tree()
	if err != nil {
		return scannerReport, err
	}
	wt, err := us.repo.Worktree()
	if err != nil {
		return scannerReport, err
	}

	status, err := wt.Status()
	if err != nil {
		return scannerReport, err
	}
	for fn, state := range status {
		var (
			prevFileContents string
			currFileContents string
			filename         string
		)

		if state.Staging != git.Untracked {
			if state.Staging == git.Deleted {
				// file in staging has been deleted, aka it is not on the filesystem
				// so the contents of the file are ""
				currFileContents = ""
			} else {
				workTreeBuf := bytes.NewBuffer(nil)
				workTreeFile, err := wt.Filesystem.Open(fn)
				if err != nil {
					continue
				}
				if _, err := io.Copy(workTreeBuf, workTreeFile); err != nil {
					return scannerReport, err
				}
				currFileContents = workTreeBuf.String()
				filename = workTreeFile.Name()
			}

			// get files at HEAD state
			prevFile, err := prevTree.File(fn)
			if err != nil {
				prevFileContents = ""

			} else {
				prevFileContents, err = prevFile.Contents()
				if err != nil {
					return scannerReport, err
				}
				if filename == "" {
					filename = prevFile.Name
				}
			}

			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(prevFileContents, currFileContents, false)
			prettyDiff := diffPrettyText(diffs)

			var diffContents string
			for _, d := range diffs {
				if d.Type == diffmatchpatch.DiffInsert {
					diffContents += fmt.Sprintf("%s\n", d.Text)
				}
			}

			lineLookup := make(map[string]bool)

			for _, line := range strings.Split(diffContents, "\n") {
				for _, rule := range us.cfg.Rules {
					offender := rule.Inspect(line)
					if offender == "" {
						continue
					}
					if us.cfg.Allowlist.RegexAllowed(line) ||
						rule.AllowList.FileAllowed(filepath.Base(filename)) ||
						rule.AllowList.PathAllowed(filename) {
						continue
					}
					if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(filename)) {
						continue
					}
					if rule.Path.String() != "" && !rule.HasFilePathLeak(filepath.Base(filename)) {
						continue
					}
					leak := NewLeak(line, offender, defaultLineNumber).WithCommit(emptyCommit())
					leak.File = filename
					leak.LineNumber = extractLine(prettyDiff, leak, lineLookup) + 1
					leak.Repo = us.repoName
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")
					if us.opts.Verbose {
						leak.Log(us.opts.Redact)
					}
					scannerReport.Leaks = append(scannerReport.Leaks, leak)
				}
			}
		}
	}

	return scannerReport, err
}

// DiffPrettyText converts a []Diff into a colored text report.
// TODO open PR for this
func diffPrettyText(diffs []diffmatchpatch.Diff) string {
	var buff bytes.Buffer
	for _, diff := range diffs {
		text := diff.Text

		switch diff.Type {
		case diffmatchpatch.DiffInsert:
			_, _ = buff.WriteString("+")
			_, _ = buff.WriteString(text)
		case diffmatchpatch.DiffDelete:
			_, _ = buff.WriteString("-")
			_, _ = buff.WriteString(text)
		case diffmatchpatch.DiffEqual:
			_, _ = buff.WriteString(" ")
			_, _ = buff.WriteString(text)
		}
	}
	return buff.String()
}
