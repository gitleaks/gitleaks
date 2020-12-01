package scan

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type UnstagedScanner struct {
	BaseScanner
	repo     *git.Repository
	repoName string
}

func NewUnstagedScanner(base BaseScanner, repo *git.Repository) *UnstagedScanner {
	us := &UnstagedScanner{
		BaseScanner: base,
		repo:        repo,
		repoName:    getRepoName(base.opts),
	}
	us.scannerType = TypeUnstagedScanner
	return us
}

func (us *UnstagedScanner) Scan() (Report, error) {
	var report Report
	r, err := us.repo.Head()
	if err == plumbing.ErrReferenceNotFound {
		wt, err := us.repo.Worktree()
		if err != nil {
			return report, err
		}

		status, err := wt.Status()
		if err != nil {
			return report, err
		}
		for fn := range status {
			workTreeBuf := bytes.NewBuffer(nil)
			workTreeFile, err := wt.Filesystem.Open(fn)
			if err != nil {
				continue
			}
			if _, err := io.Copy(workTreeBuf, workTreeFile); err != nil {
				return report, err
			}
			report.Leaks = append(report.Leaks, checkRules(us.BaseScanner, emptyCommit(), us.repoName, workTreeFile.Name(), workTreeBuf.String())...)
		}
		return report, nil
	} else if err != nil {
		return report, err
	}

	c, err := us.repo.CommitObject(r.Hash())
	if err != nil {
		return report, err
	}

	// Staged change so the Commit details do not yet exist. Insert empty defaults.
	c.Hash = plumbing.Hash{}
	c.Message = "***STAGED CHANGES***"
	c.Author.Name = ""
	c.Author.Email = ""
	c.Author.When = time.Unix(0, 0).UTC()

	prevTree, err := c.Tree()
	if err != nil {
		return report, err
	}
	wt, err := us.repo.Worktree()
	if err != nil {
		return report, err
	}

	status, err := wt.Status()
	if err != nil {
		return report, err
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
					return report, err
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
					return report, err
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
							report.Leaks = append(report.Leaks, leak)
							break
						}
					}
				}
			}
		}
	}

	return report, err
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
