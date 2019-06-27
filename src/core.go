package gitleaks

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"sync"
)

var (
	opts         *Options
	config       *Config
	dir          string
	threads      int
	totalCommits int64
	mutex        = &sync.Mutex{}
)

func init() {
	log.SetOutput(os.Stdout)
	threads = defaultThreadNum
}

// Report can be exported as a json or csv. Used for logging informationn
// about the audit, (duration and # of commits)
type Report struct {
	Leaks    []Leak
	Duration string
	Commits  int64
}

// Run is the entry point for gitleaks
func Run(optsL *Options) error {
	var (
		err   error
	)

	opts = optsL
	config, err = newConfig()
	if err != nil {
		return err
	}

	if opts.Disk {
		// temporary directory where all the gitleaks plain clones will reside
		dir, err = ioutil.TempDir("", "gitleaks")
		defer os.RemoveAll(dir)
		if err != nil {
			return err
		}
	}

	// start audits
	if opts.Repo != "" || opts.RepoPath != "" {
		var repo *Repo
		repo, err = newRepo()
		if err != nil {
			return err
		}
		err = repo.clone()
		if err != nil {
			return err
		}
		err = repo.audit()
		if err != nil {
			return err
		}
		err = repo.report()
		if err != nil {
			return err
		}
	} else if opts.OwnerPath != "" {
		var repos []*Repo
		repos, err = discoverRepos(opts.OwnerPath)
		if err != nil {
			return err
		}
		for _, repo := range repos {
			err = repo.clone()
			if err != nil {
				log.Warnf("error occurred cloning repo: %s, continuing to next repo", repo.name)
				continue
			}
			err = repo.audit()
			if err != nil {
				log.Warnf("error occured auditing repo: %s, continuing to next repo", repo.name)
				continue
			}
			err = repo.report()
			if err != nil {
				return err
			}
		}
	} else if opts.GithubOrg != "" || opts.GithubUser != "" {
		return auditGithubRepos()
	} else if opts.GitLabOrg != "" || opts.GitLabUser != "" {
		return auditGitlabRepos()
	} else if opts.GithubPR != "" {
		return auditGithubPR()
	}

	return nil
}
