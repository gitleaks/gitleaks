package scan

import (
	"fmt"
	"github.com/go-git/go-git/v5/plumbing"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/zricethezav/gitleaks/v6/manager"
	"github.com/zricethezav/gitleaks/v6/repo"
	"time"
)

type CommitScanner struct {
	repo      *repo.Repo
	commit *object.Commit
}

func NewCommitScanner(commits string, repo *repo.Repo) (*CommitScanner, error) {
	return &CommitScanner{
		repo:   nil,
		commit: nil,
	}, nil
}

func (c *CommitScanner) Scan() error {
	return nil
}

// scanCommit accepts a Commit hash, repo, and commit scanning function. A new Commit
// object will be created from the hash which will be passed into either scanCommitPatches
// or scanFilesAtCommit depending on the options set.
func scanCommit(commit string, repo *Repo, f commitScanner) error {
	if commit == "latest" {
		ref, err := repo.Repository.Head()
		if err != nil {
			return err
		}
		commit = ref.Hash().String()
	}
	repo.Manager.IncrementCommits(1)
	h := plumbing.NewHash(commit)
	c, err := repo.CommitObject(h)
	if err != nil {
		return err
	}
	return f(c, repo)
}

// scanCommitPatches accepts a Commit object and a repo. This function is only called when the --Commit=
// option has been set. That option tells gitleaks to look only at a single Commit and check the contents
// of said Commit. Similar to scan(), if the files contained in the Commit are a binaries or if they are
// allowlisted then those files will be skipped.
func scanCommitPatches(c *object.Commit, repo *Repo) error {
	if len(c.ParentHashes) == 0 {
		err := scanFilesAtCommit(c, repo)
		if err != nil {
			return err
		}
	}

	return c.Parents().ForEach(func(parent *object.Commit) error {
		defer func() {
			if err := recover(); err != nil {
				// sometimes the Patch generation will fail due to a known bug in
				// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
				// Once a fix has been merged I will remove this recover.
				return
			}
		}()
		if repo.timeoutReached() {
			return nil
		}
		if parent == nil {
			return nil
		}
		start := time.Now()
		patch, err := parent.Patch(c)
		if err != nil {
			return fmt.Errorf("could not generate Patch")
		}
		repo.Manager.RecordTime(manager.PatchTime(howLong(start)))

		scanPatch(patch, c, repo)

		return nil
	})
}

// scanFilesAtCommit accepts a Commit object and a repo. This function is only called when the --files-at-Commit=
// option has been set. That option tells gitleaks to look only at ALL the files at a Commit and check the contents
// of said Commit. Similar to scan(), if the files contained in the Commit are a binaries or if they are
// allowlisted then those files will be skipped.
func scanFilesAtCommit(c *object.Commit, repo *Repo) error {
	fIter, err := c.Files()
	if err != nil {
		return err
	}

	err = fIter.ForEach(func(f *object.File) error {
		bin, err := f.IsBinary()
		if bin || repo.timeoutReached() {
			return nil
		} else if err != nil {
			return err
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}

		repo.CheckRules(&Source{
			Content:   content,
			FilePath:  f.Name,
			Commit:    c,
			scanType:  commitScan,
			Operation: fdiff.Add,
		})
		return nil
	})
	return err
}
