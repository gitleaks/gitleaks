package scan

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

// RepoScanner is a repo scanner
type RepoScanner struct {
	BaseScanner
	repo     *git.Repository
	repoName string

	leakChan  chan Leak
	leakWG    *sync.WaitGroup
	leakCache map[string]bool
	leaks     []Leak
}

// NewRepoScanner returns a new repo scanner (go figure). This function also
// sets up the leak listener for multi-threaded awesomeness.
func NewRepoScanner(base BaseScanner, repo *git.Repository) *RepoScanner {
	rs := &RepoScanner{
		BaseScanner: base,
		repo:        repo,
		leakChan:    make(chan Leak),
		leakWG:      &sync.WaitGroup{},
		leakCache:   make(map[string]bool),
		repoName:    getRepoName(base.opts),
	}

	rs.scannerType = typeRepoScanner

	go rs.receiveLeaks()

	return rs
}

// Scan kicks of a repo scan
func (rs *RepoScanner) Scan() (Report, error) {
	var scannerReport Report
	logOpts, err := logOptions(rs.repo, rs.opts)
	if err != nil {
		return scannerReport, err
	}
	cIter, err := rs.repo.Log(logOpts)
	if err != nil {
		return scannerReport, err
	}
	semaphore := make(chan bool, howManyThreads(rs.opts.Threads))
	wg := sync.WaitGroup{}

	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || depthReached(scannerReport.Commits, rs.opts) {
			return storer.ErrStop
		}

		if rs.cfg.Allowlist.CommitAllowed(c.Hash.String()) {
			return nil
		}

		// Check if at root
		if len(c.ParentHashes) == 0 {
			scannerReport.Commits++
			facScanner := NewFilesAtCommitScanner(rs.BaseScanner, rs.repo, c)
			facScanner.repoName = rs.repoName
			facReport, err := facScanner.Scan()
			if err != nil {
				return err
			}
			scannerReport.Leaks = append(scannerReport.Leaks, facReport.Leaks...)
			return nil
		}

		// inspect first parent only as all other parents will be eventually reached
		// (they exist as the tip of other branches, etc)
		// See https://github.com/zricethezav/gitleaks/issues/413 for details
		parent, err := c.Parent(0)
		if err != nil || parent == nil {
			return err
		}
		patch, err := parent.Patch(c)
		if err != nil {
			return fmt.Errorf("could not generate Patch")
		}

		scannerReport.Commits++
		wg.Add(1)
		semaphore <- true
		go func(c *object.Commit, patch *object.Patch) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			commitScanner := NewCommitScanner(rs.BaseScanner, rs.repo, c)
			commitScanner.SetRepoName(rs.repoName)
			commitScanner.SetPatch(patch)
			report, err := commitScanner.Scan()
			if err != nil {
				log.Error(err)
			}
			for _, leak := range report.Leaks {
				rs.leakWG.Add(1)
				rs.leakChan <- leak
			}
		}(c, patch)

		if c.Hash.String() == rs.opts.CommitTo {
			return storer.ErrStop
		}
		return nil
	})

	wg.Wait()
	rs.leakWG.Wait()
	scannerReport.Leaks = append(scannerReport.Leaks, rs.leaks...)
	return scannerReport, nil
}

func (rs *RepoScanner) receiveLeaks() {
	for leak := range rs.leakChan {
		rs.leaks = append(rs.leaks, leak)
		rs.leakWG.Done()
	}
}
