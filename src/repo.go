package gitleaks

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	diffType "gopkg.in/src-d/go-git.v4/plumbing/format/diff"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/storer"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

// RepoInfo contains a src-d git repository and other data about the repo
type RepoInfo struct {
	path       string
	url        string
	name       string
	repository *git.Repository
	err        error
}

func newRepoInfo() (*RepoInfo, error) {
	for _, re := range config.WhiteList.repos {
		if re.FindString(opts.Repo) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", opts.Repo)
		}
	}
	return &RepoInfo{
		path: opts.RepoPath,
		url:  opts.Repo,
		name: filepath.Base(opts.Repo),
	}, nil
}

func (repoD *RepoInfo) clone() error {
	var (
		err  error
		repo *git.Repository
	)

	// check if cloning to disk
	if opts.Disk {
		log.Infof("cloning %s to disk", opts.Repo)
		cloneTarget := fmt.Sprintf("%s/%x", dir, md5.Sum([]byte(fmt.Sprintf("%s%s", opts.GithubUser, opts.Repo))))
		if strings.HasPrefix(opts.Repo, "git") {
			// private
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
			})
		} else {
			// public
			repo, err = git.PlainClone(cloneTarget, false, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	} else if repoD.path != "" {
		log.Infof("opening %s", opts.RepoPath)
		repo, err = git.PlainOpen(repoD.path)
	} else {
		// cloning to memory
		log.Infof("cloning %s", opts.Repo)
		if strings.HasPrefix(opts.Repo, "git") {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
				Auth:     config.sshAuth,
			})
		} else {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:      opts.Repo,
				Progress: os.Stdout,
			})
		}
	}
	repoD.repository = repo
	repoD.err = err
	return err
}

func (repoD *RepoInfo) audit() ([]Leak, error) {
	var (
		err   error
		leaks []Leak
	)
	for _, re := range config.WhiteList.repos {
		if re.FindString(repoD.name) != "" {
			return leaks, fmt.Errorf("skipping %s, whitelisted", repoD.name)
		}
	}

	// check if target contains an external gitleaks toml
	if opts.RepoConfig {
		err := config.updateFromRepo(repoD)
		if err != nil {
			return leaks, nil
		}
	}

	// clear commit cache
	commitMap = make(map[string]bool)

	refs, err := repoD.repository.Storer.IterReferences()
	if err != nil {
		return leaks, err
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Name().IsTag() {
			return nil
		}
		branchLeaks := repoD.auditRef(ref)
		for _, leak := range branchLeaks {
			leaks = append(leaks, leak)
		}
		return nil
	})
	return leaks, err
}

// auditGitReference beings the audit for a git reference. This function will
// traverse the git reference and audit each line of each diff.
func (repoD *RepoInfo) auditRef(ref *plumbing.Reference) []Leak {
	var (
		err         error
		repoName    string
		leaks       []Leak
		commitCount int64
		commitWg    sync.WaitGroup
		mutex       = &sync.Mutex{}
		semaphore   chan bool
	)
	if auditDone {
		return nil
	}
	repoName = repoD.name
	if opts.Threads != 0 {
		threads = opts.Threads
	}
	if opts.RepoPath != "" {
		threads = 1
	}
	semaphore = make(chan bool, threads)

	cIter, err := repoD.repository.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil
	}
	err = cIter.ForEach(func(c *object.Commit) error {
		if c == nil || (opts.Depth != 0 && commitCount == opts.Depth) || auditDone {
			if commitCount == opts.Depth {
				auditDone = true
			}
			return storer.ErrStop
		}
		commitCount = commitCount + 1
		if config.WhiteList.commits[c.Hash.String()] {
			log.Infof("skipping commit: %s\n", c.Hash.String())
			return nil
		}

		// commits w/o parent (root of git the git ref) or option for single commit is not empty str
		if len(c.ParentHashes) == 0 || opts.Commit == c.Hash.String() {
			if commitMap[c.Hash.String()] {
				return nil
			}

			if opts.Commit == c.Hash.String() {
				auditDone = true
			}

			cMutex.Lock()
			commitMap[c.Hash.String()] = true
			cMutex.Unlock()
			totalCommits = totalCommits + 1

			fIter, err := c.Files()
			if err != nil {
				return nil
			}
			err = fIter.ForEach(func(f *object.File) error {
				bin, err := f.IsBinary()
				if bin || err != nil {
					return nil
				}
				for _, re := range config.WhiteList.files {
					if re.FindString(f.Name) != "" {
						log.Debugf("skipping whitelisted file (matched regex '%s'): %s", re.String(), f.Name)
						return nil
					}
				}
				content, err := f.Contents()
				if err != nil {
					return nil
				}
				diff := gitDiff{
					repoName: repoName,
					filePath: f.Name,
					content:  content,
					sha:      c.Hash.String(),
					author:   c.Author.String(),
					message:  strings.Replace(c.Message, "\n", " ", -1),
					date:     c.Author.When,
				}
				fileLeaks := inspect(diff)
				mutex.Lock()
				leaks = append(leaks, fileLeaks...)
				mutex.Unlock()
				return nil
			})
			return nil
		}

		// single commit
		if opts.Commit != "" {
			return nil
		}

		skipCount := false
		err = c.Parents().ForEach(func(parent *object.Commit) error {
			// check if we've seen this diff before
			if commitMap[c.Hash.String()+parent.Hash.String()] {
				return nil
			}
			cMutex.Lock()
			commitMap[c.Hash.String()+parent.Hash.String()] = true
			cMutex.Unlock()

			if !skipCount {
				totalCommits = totalCommits + 1
				skipCount = true
			}

			commitWg.Add(1)
			semaphore <- true
			go func(c *object.Commit, parent *object.Commit) {
				var (
					filePath string
					skipFile bool
				)
				defer func() {
					commitWg.Done()
					<-semaphore
					if r := recover(); r != nil {
						log.Warnf("recovering from panic on commit %s, likely large diff causing panic", c.Hash.String())
					}
				}()
				patch, err := c.Patch(parent)
				if err != nil {
					log.Warnf("problem generating patch for commit: %s\n", c.Hash.String())
					return
				}
				for _, f := range patch.FilePatches() {
					if f.IsBinary() {
						continue
					}
					skipFile = false
					from, to := f.Files()
					filePath = "???"
					if from != nil {
						filePath = from.Path()
					} else if to != nil {
						filePath = to.Path()
					}
					for _, re := range config.WhiteList.files {
						if re.FindString(filePath) != "" {
							log.Debugf("skipping whitelisted file (matched regex '%s'): %s", re.String(), filePath)
							skipFile = true
							break
						}
					}
					if skipFile {
						continue
					}
					chunks := f.Chunks()
					for _, chunk := range chunks {
						if chunk.Type() == diffType.Add || chunk.Type() == diffType.Delete {
							diff := gitDiff{
								repoName: repoName,
								filePath: filePath,
								content:  chunk.Content(),
								sha:      c.Hash.String(),
								author:   c.Author.String(),
								message:  strings.Replace(c.Message, "\n", " ", -1),
								date:     c.Author.When,
							}
							chunkLeaks := inspect(diff)
							for _, leak := range chunkLeaks {
								mutex.Lock()
								leaks = append(leaks, leak)
								mutex.Unlock()
							}
						}
					}
				}
			}(c, parent)

			return nil
		})

		// stop audit if we are at commitStop
		if c.Hash.String() == opts.CommitStop {
			auditDone = true
			return storer.ErrStop
		}

		return nil
	})
	commitWg.Wait()
	return leaks
}
