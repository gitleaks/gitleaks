package scan

import (
	"bytes"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/zricethezav/gitleaks/v6/manager"
	"github.com/zricethezav/gitleaks/v6/repo"
	"io"
	"time"
)

type UnstagedScanner struct {
	repo      *repo.Repo
}

func NewUnstagedScanner(repo *repo.Repo) (*UnstagedScanner, error) {
	return &UnstagedScanner{
		repo:   nil,
	}, nil
}

func (scanner *UnstagedScanner) Scan() error {
	return nil
}

// scanUncommitted will do a `git diff` and scan changed files that are being tracked. This is useful functionality
// for a pre-Commit hook so you can make sure your code does not have any leaks before committing.
func (repo *Repo) scanUncommitted() error {
	// load up alternative config if possible, if not use manager's config
	if repo.Manager.Opts.RepoConfig {
		cfg, err := repo.loadRepoConfig()
		if err != nil {
			return err
		}
		repo.config = cfg
	}

	if err := repo.setupTimeout(); err != nil {
		return err
	}

	r, err := repo.Head()
	if err == plumbing.ErrReferenceNotFound {
		// possibly an empty repo, or maybe its not, either way lets scan all the files in the directory
		return repo.scanEmpty()
	} else if err != nil {
		return err
	}

	scanTimeStart := time.Now()

	c, err := repo.CommitObject(r.Hash())
	if err != nil {
		return err
	}
	// Staged change so the Commit details do not yet exist. Insert empty defaults.
	c.Hash = plumbing.Hash{}
	c.Message = "***STAGED CHANGES***"
	c.Author.Name = ""
	c.Author.Email = ""
	c.Author.When = time.Unix(0, 0).UTC()

	prevTree, err := c.Tree()
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	status, err := wt.Status()
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
					return err
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
					return err
				}
				if filename == "" {
					filename = prevFile.Name
				}
			}

			dmp := diffmatchpatch.New()
			diffs := dmp.DiffCleanupSemantic(dmp.DiffMain(prevFileContents, currFileContents, false))
			var diffContents string
			for _, d := range diffs {
				if d.Type == diffmatchpatch.DiffInsert {
					diffContents += fmt.Sprintf("%s\n", d.Text)
				}
			}
			repo.CheckRules(&Source{
				Content:  diffContents,
				FilePath: filename,
				Commit:   c,
				scanType: uncommittedScan,
			})
		}
	}

	if err != nil {
		return err
	}
	repo.Manager.RecordTime(manager.ScanTime(howLong(scanTimeStart)))
	return nil
}
