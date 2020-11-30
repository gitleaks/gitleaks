package scan

import (
	"github.com/go-git/go-git/v5"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	log "github.com/sirupsen/logrus"
	"sync"
)

type RepoScanner struct {
	BaseScanner
	repo *git.Repository
	repoName string

	leakChan  chan Leak
	leakWG    *sync.WaitGroup
	leakCache map[string]bool
	leaks []Leak
}

func NewRepoScanner(base BaseScanner, repo *git.Repository) *RepoScanner {
	rs := &RepoScanner{
		BaseScanner: base,
		repo:        repo,
		leakChan:    make(chan Leak),
		leakWG:      &sync.WaitGroup{},
		leakCache:   make(map[string]bool),
		repoName: getRepoName(base.opts),
	}

	rs.scannerType = TypeRepoScanner

	go rs.receiveLeaks()

	return rs
}

func (rs *RepoScanner) Scan() (Report, error) {
	var report Report
	logOpts, err := logOptions(rs.repo, rs.opts)
	if err != nil {
		return report, err
	}
	cIter, err := rs.repo.Log(logOpts)
	if err != nil {
		return report, err
	}
	semaphore := make(chan bool, howManyThreads(rs.opts.Threads))
	wg := sync.WaitGroup{}

	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || depthReached(report.Commits, rs.opts) {
			return storer.ErrStop
		}

		// Check if Commit is allowlisted
		if isCommitAllowListed(c.Hash.String(), rs.cfg.Allowlist.Commits) {
			return nil
		}

		// Check if at root
		if len(c.ParentHashes) == 0 {
			report.Commits++
			facScanner := NewFilesAtCommitScanner(rs.BaseScanner, rs.repo, c)
			facScanner.repoName = rs.repoName
			facReport, err := facScanner.Scan()
			if err != nil {
				return err
			}
			rs.leaks = append(rs.leaks, facReport.Leaks...)
			return nil
		}

		report.Commits++

		// inspect first parent only as all other parents will be eventually reached
		// (they exist as the tip of other branches, etc)
		// See https://github.com/zricethezav/gitleaks/issues/413 for details
		parent, err := c.Parent(0)
		if err != nil {
			return err
		}

		defer func() {
			if err := recover(); err != nil {
				// sometimes the Patch generation will fail due to a known bug in
				// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
				// Once a fix has been merged I will remove this recover.
				return
			}
		}()

		if parent == nil {
			// shouldn't reach this point but just in case
			return nil
		}

		// start := time.Now()
		patch, err := parent.Patch(c)
		if err != nil {
			log.Errorf("could not generate Patch")
		}

		wg.Add(1)
		semaphore <- true
		go func(c *object.Commit, patch *object.Patch) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			// patchContent is used for searching for leak line number
			patchContent := patch.String()

			for _, f := range patch.FilePatches() {
				if f.IsBinary() {
					continue
				}

				for _, chunk := range f.Chunks() {
					if chunk.Type() == fdiff.Add {
						_, to := f.Files()
						lineLookup := make(map[string]bool)
						for _, leak := range checkRules(rs.BaseScanner, c, rs.repoName, to.Path(), chunk.Content()) {
							leak.LineNumber = extractLine(patchContent, leak, lineLookup)
							if rs.opts.Verbose {
								logLeak(leak)
							}
							rs.leakWG.Add(1)
							rs.leakChan <- leak
						}
					}
				}
			}
		}(c, patch)

		if c.Hash.String() == rs.opts.CommitTo {
			return storer.ErrStop
		}
		return nil
	})

	wg.Wait()
	rs.leakWG.Wait()
	report.Leaks = rs.leaks
	return report, nil
}

func (rs *RepoScanner) receiveLeaks() {
	for leak := range rs.leakChan {
		rs.leaks = append(rs.leaks, leak)
		rs.leakWG.Done()
	}
}
