package scan

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v7/report"

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
func (us *UnstagedScanner) Scan() (report.Report, error) {
	var scannerReport report.Report
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
			leaks := checkRules(us.BaseScanner, emptyCommit(), us.repoName, workTreeFile.Name(), workTreeBuf.String())
			for _, leak := range leaks {
				if us.opts.Verbose {
					logLeak(leak, us.opts.Redact)
				}
				scannerReport.Leaks = append(scannerReport.Leaks, leak)
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

	status, err := gitStatus(wt)
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
			leaks := checkRules(us.BaseScanner, c, us.repoName, filename, diffContents)

			lineLookup := make(map[string]bool)
			for _, leak := range leaks {
				for lineNumber, line := range strings.Split(prettyDiff, "\n") {
					if strings.HasPrefix(line, diffAddPrefix) && strings.Contains(line, leak.Line) {
						if _, ok := lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, leak.File)]; !ok {
							lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, leak.File)] = true
							leak.LineNumber = lineNumber + 1
							if us.opts.Verbose {
								logLeak(leak, us.opts.Redact)
							}
							scannerReport.Leaks = append(scannerReport.Leaks, leak)
							break
						}
					}
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
			_, _ = buff.WriteString(text)
		}
	}
	return buff.String()
}

// gitStatus returns the status of modified files in the worktree. It will attempt to execute 'git status'
// and will fall back to git.Worktree.Status() if that fails.
func gitStatus(wt *git.Worktree) (git.Status, error) {
	c := exec.Command("git", "status", "--porcelain", "-z")
	c.Dir = wt.Filesystem.Root()
	output, err := c.Output()
	if err != nil {
		stat, err := wt.Status()
		return stat, err
	}

	lines := strings.Split(string(output), "\000")
	stat := make(map[string]*git.FileStatus, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		// For copy/rename the output looks like
		//   R  destination\000source
		// Which means we can split on space and ignore anything with only one result
		parts := strings.SplitN(strings.TrimLeft(line, " "), " ", 2)
		if len(parts) == 2 {
			stat[strings.Trim(parts[1], " ")] = &git.FileStatus{
				Staging: git.StatusCode([]byte(parts[0])[0]),
			}
		}
	}
	return stat, err
}
