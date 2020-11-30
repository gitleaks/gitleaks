package scan

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type CommitScanner struct {
	BaseScanner
	repo     *git.Repository
	repoName string
	commit   *object.Commit
	leaks    []Leak
}

func NewCommitScanner(base BaseScanner, repo *git.Repository, commit *object.Commit) *CommitScanner {
	cs := &CommitScanner{
		BaseScanner: base,
		repo:        repo,
		commit:      commit,
		repoName:    getRepoName(base.opts),
	}
	cs.scannerType = TypeCommitScanner
	return cs
}

func (cs *CommitScanner) Scan() ([]Leak, error) {
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
		if timeoutReached(cs.ctx) {
			return nil
		}
		if parent == nil {
			return nil
		}

		patch, err := parent.Patch(cs.commit)
		if err != nil {
			return fmt.Errorf("could not generate Patch")
		}

		patchContent := patch.String()

		for _, f := range patch.FilePatches() {
			if timeoutReached(cs.ctx) {
				return nil
			}
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
						cs.leaks = append(cs.leaks, leak)
					}
				}
			}
		}
		return nil
	})
	return cs.leaks, err
}
