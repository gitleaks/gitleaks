package scan

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	log "github.com/sirupsen/logrus"
)

type RepoScanner struct {
	BaseScanner
	repo *git.Repository

	stopChan  chan os.Signal
	leaks     []Leak
	leakChan  chan Leak
	leakWG    *sync.WaitGroup
	leakCache map[string]bool
}

func NewRepoScanner(base BaseScanner, repo *git.Repository) *RepoScanner {
	rs := &RepoScanner{
		BaseScanner: base,
		repo:        repo,
		stopChan:    make(chan os.Signal, 1),
		leakChan:    make(chan Leak),
		leakWG:      &sync.WaitGroup{},
		leakCache:   make(map[string]bool),
	}

	// setup signal stuff
	signal.Notify(rs.stopChan, os.Interrupt)

	go rs.receiveLeaks()

	return rs
}

func (rs *RepoScanner) Scan() error {
	logOpts, err := logOptions(rs.repo, rs.opts)
	if err != nil {
		return err
	}
	cIter, err := rs.repo.Log(logOpts)
	if err != nil {
		return err
	}

	cc := 0
	semaphore := make(chan bool, howManyThreads(rs.opts.Threads))
	wg := sync.WaitGroup{}

	// TODO FINISH REPOSCAN!
	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || timeoutReached(rs.ctx) || depthReached(cc, rs.opts) {
			return storer.ErrStop
		}

		// Check if Commit is allowlisted
		if isCommitAllowListed(c.Hash.String(), rs.cfg.Allowlist.Commits) {
			return nil
		}

		// Check if at root
		if len(c.ParentHashes) == 0 {
			cc++
			facScanner := NewFilesAtCommitScanner(rs.BaseScanner, rs.repo, c)
			if err := facScanner.Scan(); err != nil {
				return err
			}
			rs.leaks = append(rs.leaks, facScanner.GetLeaks()...)
			return nil
		}

		// increase Commit counter
		cc++

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

		if timeoutReached(rs.ctx) {
			return nil
		}
		if parent == nil {
			// shouldn't reach this point but just in case
			return nil
		}

		// start := time.Now()
		patch, err := parent.Patch(c)
		if err != nil {
			log.Errorf("could not generate Patch")
		}
		// TODO Record time
		// repo.Manager.RecordTime(manager.PatchTime(howLong(start)))

		wg.Add(1)
		semaphore <- true
		go func(c *object.Commit, patch *object.Patch) {
			defer func() {
				<-semaphore
				wg.Done()
			}()
			for _, f := range patch.FilePatches() {
				if timeoutReached(rs.ctx) {
					return
				}
				if f.IsBinary() {
					continue
				}

				patchContent := patch.String()

				for _, chunk := range f.Chunks() {
					if chunk.Type() == fdiff.Add || (rs.opts.Deletion && chunk.Type() == fdiff.Delete) {
						from, to := f.Files()
						var filepath string
						if from != nil {
							filepath = from.Path()
						} else if to != nil {
							filepath = to.Path()
						} else {
							filepath = "???"
						}
						//
						//obj, err := object.GetBlob(rs.repo.Storer, from.Hash())
						//if err != nil {
						//	return
						//}
						//r, err := obj.Reader()
						//if err != nil {
						//	return
						//}
						//s := bufio.NewScanner(r)
						//s.Split(bufio.ScanLines)
						//for s.Scan() {
						//	l := s.Text()
						//	fmt.Println(l)
						//}

						lineLookup := make(map[string]bool)

						for _, leak := range checkRules(rs.cfg, "", filepath, c, chunk.Content()) {
							i := strings.Index(patchContent, fmt.Sprintf("\n+++ b/%s", leak.File))
							filePatchContent := patchContent[i+1:]
							i = strings.Index(filePatchContent, "diff --git")
							if i != -1 {
								filePatchContent = filePatchContent[:i]
							}
							chunkStartLine := 0
							currLine := 0
							for _, patchLine := range strings.Split(filePatchContent, "\n") {
								if strings.HasPrefix(patchLine, "@@") {
									i := strings.Index(patchLine, diffAddPrefix)
									pairs := strings.Split(strings.Split(patchLine[i+1:], diffLineSignature)[0], ",")
									chunkStartLine, _ = strconv.Atoi(pairs[0])
									currLine = -1
								}
								if strings.HasPrefix(patchLine, diffAddPrefix) && strings.Contains(patchLine, leak.Line) {
									lineNumber := chunkStartLine + currLine
									if _, ok := lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, filepath)]; !ok {
										lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, filepath)] = true
										leak.LineNumber = lineNumber
										break
									}
								}
								currLine++
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
	// TODO Record Time
	//repo.Manager.RecordTime(manager.ScanTime(howLong(scanTimeStart)))
	//repo.Manager.IncrementCommits(cc)
	fmt.Println("DONE")
	return nil
}

func (rs *RepoScanner) receiveLeaks() {
	for leak := range rs.leakChan {
		rs.leaks = append(rs.leaks, leak)
		rs.leakWG.Done()
	}
}

func (rs *RepoScanner) GetLeaks() []Leak {
	rs.leakWG.Wait()
	return rs.leaks
}
