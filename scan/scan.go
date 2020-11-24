package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/zricethezav/gitleaks/v6/options"
	"github.com/zricethezav/gitleaks/v6/repo"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/zricethezav/gitleaks/v6/manager"

	"github.com/go-git/go-git/v5/plumbing"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	log "github.com/sirupsen/logrus"
)

// Source contains various git information for scans.
type Source struct {
	Commit    *object.Commit
	Content   string
	FilePath  string
	Operation fdiff.Operation

	reader     io.Reader
	lineLookup map[string]bool
	scanType   int
}

type ScannerType uint8
const (
	UnstagedScan ScannerType = iota + 1
	CommitScan
	CommitsScan
	FilesAtCommitScan
	RepoScan
)

type Scanner interface {
	Scan() error
}

// Start begins the initial work of a gitleaks scan. This will determine the scan type and open
// the necessary files, commits, repos, etc.
func Start(m *manager.Manager) error {
	if m.Opts.OwnerPath != "" {
		files, err := ioutil.ReadDir(m.Opts.OwnerPath)
		if err != nil {
			return err
		}
		for _, f := range files {
			if !f.IsDir() {
				continue
			}
			m.Opts.RepoPath = fmt.Sprintf("%s/%s", m.Opts.OwnerPath, f.Name())
			if err := runHelper(repo.NewRepo(m)); err != nil {
				log.Warnf("%s is not a git repo, skipping", f.Name())
			}
		}
		return nil
	}

	return runHelper(repo.NewRepo(m))

	return nil
}

func runHelper(r *repo.Repo) error {
	var (
		scanner Scanner
		err error
	)

	// Ignore allowlisted repos
	for _, allowListedRepo := range r.Manager.Config.Allowlist.Repos {
		if RegexMatched(r.Manager.Opts.RepoPath, allowListedRepo) {
			return nil
		}
		if RegexMatched(r.Manager.Opts.Repo, allowListedRepo) {
			return nil
		}
	}

	// either clone or open existing repo
	if r.Manager.Opts.OpenLocal() {
		r.Name = path.Base(r.Manager.Opts.RepoPath)
		if err := r.Open(); err != nil {
			return err
		}
	} else {
		if err := r.Clone(nil); err != nil {
			return err
		}
	}

	// setup scanner
	switch getScannerType(r.Manager.Opts) {
	case CommitScan:
		scanner, err = NewCommitScanner("", r)
	case CommitsScan:
		scanner, err = NewCommitsScanner([]string{""}, r)
	case UnstagedScan:
		scanner, err = NewUnstagedScanner(r)
	case FilesAtCommitScan:
		scanner, err = NewCommitsScanner([]string{""}, r)
	case RepoScan:
		scanner, err = NewCommitsScanner([]string{""}, r)
	}
	if err != nil {
		return err
	}
	return scanner.Scan()
}

func getScannerType(opts options.Options) ScannerType {
	if opts.Commit != "" {
		return CommitScan
	}
	if opts.Commits != "" || opts.CommitsFile != "" {
		return CommitScan
	}
	if opts.FilesAtCommit != "" {
		return FilesAtCommitScan
	}
	if opts.CheckUncommitted() {
		return UnstagedScan
	}

	return RepoScan
}

func setUpScanner(repo *repo.Repo) {
	if err := repo.setupTimeout(); err != nil {
		return err
	}
	if repo.cancel != nil {
		defer repo.cancel()
	}

	if repo.Repository == nil {
		return fmt.Errorf("%s repo is empty", repo.Name)
	}

	// load up alternative config if possible, if not use manager's config
	if repo.Manager.Opts.RepoConfig {
		cfg, err := repo.loadRepoConfig()
		if err != nil {
			return err
		}
		repo.config = cfg
	}
}




// Scan is responsible for scanning the entire history (default behavior) of a
// git repo. Options that can change the behavior of this function include: --Commit, --depth, --branch.
// See options/options.go for an explanation on these options.
func (repo *Repo) Scan() error {
	if err := repo.setupTimeout(); err != nil {
		return err
	}
	if repo.cancel != nil {
		defer repo.cancel()
	}

	if repo.Repository == nil {
		return fmt.Errorf("%s repo is empty", repo.Name)
	}

	// load up alternative config if possible, if not use manager's config
	if repo.Manager.Opts.RepoConfig {
		cfg, err := repo.loadRepoConfig()
		if err != nil {
			return err
		}
		repo.config = cfg
	}

	scanTimeStart := time.Now()

	var (
		scanner Scanner
		err error
	)
	switch repo.ScanType() {
	case CommitScan:
		scanner, err = NewCommitScanner([]string{""}, repo)

	}

	scanner.Scan()

	// See https://github.com/zricethezav/gitleaks/issues/326
	// Scan commit patches, all files at a commit, or a range of commits
	//if repo.Manager.Opts.Commit != "" {
	//	return scanCommit(repo.Manager.Opts.Commit, repo, scanCommitPatches)
	//} else if repo.Manager.Opts.FilesAtCommit != "" {
	//	return scanCommit(repo.Manager.Opts.FilesAtCommit, repo, scanFilesAtCommit)
	//} else if repo.Manager.Opts.Commits != "" {
	//	commits := strings.Split(repo.Manager.Opts.Commits, ",")
	//	for _, c := range commits {
	//		err := scanCommit(c, repo, scanCommitPatches)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//	return nil
	//} else if repo.Manager.Opts.CommitsFile != "" {
	//	file, err := os.Open(repo.Manager.Opts.CommitsFile)
	//	if err != nil {
	//		return err
	//	}
	//	defer file.Close()
	//
	//	scanner := bufio.NewScanner(file)
	//	for scanner.Scan() {
	//		err := scanCommit(scanner.Text(), repo, scanCommitPatches)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//	return nil
	//}

	logOpts, err := getLogOptions(repo)
	if err != nil {
		return err
	}
	cIter, err := repo.Log(logOpts)
	if err != nil {
		return err
	}

	cc := 0
	semaphore := make(chan bool, howManyThreads(repo.Manager.Opts.Threads))
	wg := sync.WaitGroup{}
	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || repo.timeoutReached() || repo.depthReached(cc) {
			return storer.ErrStop
		}

		// Check if Commit is allowlisted
		if isCommitAllowListed(c.Hash.String(), repo.config.Allowlist.Commits) {
			return nil
		}

		// Check if at root
		if len(c.ParentHashes) == 0 {
			cc++
			err = scanFilesAtCommit(c, repo)
			if err != nil {
				return err
			}
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
		if repo.timeoutReached() {
			return nil
		}
		if parent == nil {
			// shouldn't reach this point but just in case
			return nil
		}

		start := time.Now()
		patch, err := parent.Patch(c)
		if err != nil {
			log.Errorf("could not generate Patch")
		}
		repo.Manager.RecordTime(manager.PatchTime(howLong(start)))

		wg.Add(1)
		semaphore <- true
		go func(c *object.Commit, patch *object.Patch) {
			defer func() {
				<-semaphore
				wg.Done()
			}()
			scanPatch(patch, c, repo)
		}(c, patch)

		if c.Hash.String() == repo.Manager.Opts.CommitTo {
			return storer.ErrStop
		}
		return nil
	})

	wg.Wait()
	repo.Manager.RecordTime(manager.ScanTime(howLong(scanTimeStart)))
	repo.Manager.IncrementCommits(cc)
	return nil
}

// scanEmpty scans an empty repo without any commits. See https://github.com/zricethezav/gitleaks/issues/352
func (repo *Repo) scanEmpty() error {
	scanTimeStart := time.Now()
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	status, err := wt.Status()
	if err != nil {
		return err
	}
	for fn := range status {
		workTreeBuf := bytes.NewBuffer(nil)
		workTreeFile, err := wt.Filesystem.Open(fn)
		if err != nil {
			continue
		}
		if _, err := io.Copy(workTreeBuf, workTreeFile); err != nil {
			return err
		}
		repo.CheckRules(&Source{
			Content:  workTreeBuf.String(),
			FilePath: workTreeFile.Name(),
			Commit:   emptyCommit(),
			scanType: uncommittedScan,
		})
	}
	repo.Manager.RecordTime(manager.ScanTime(howLong(scanTimeStart)))
	return nil
}

// depthReached checks if i meets the depth (--depth=) if set
func (repo *Repo) depthReached(i int) bool {
	if repo.Manager.Opts.Depth != 0 && repo.Manager.Opts.Depth == i {
		log.Warnf("Exceeded depth limit (%d)", i)
		return true
	}
	return false
}

// emptyCommit generates an empty commit used for scanning uncommitted changes
func emptyCommit() *object.Commit {
	return &object.Commit{
		Hash:    plumbing.Hash{},
		Message: "***STAGED CHANGES***",
		Author: object.Signature{
			Name:  "",
			Email: "",
			When:  time.Unix(0, 0).UTC(),
		},
	}
}
