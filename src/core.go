package gitleaks

import (
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
)

var (
	opts              *Options
	config            *Config
	singleSearchRegex *regexp.Regexp
	dir               string
	threads           int
	totalCommits      int64
	commitMap         = make(map[string]bool)
	auditDone         bool
	mutex             = &sync.Mutex{}
)

func init() {
	log.SetOutput(os.Stdout)
	threads = defaultThreadNum
}

// Report is
type Report struct {
	Leaks    []Leak
	Duration string
	Commits  int64
}

// Run is the entry point for gitleaks
func Run(optsL *Options) (*Report, error) {
	var (
		leaks []Leak
		err   error
	)

	now := time.Now()
	opts = optsL
	config, err = newConfig()
	if err != nil {
		return nil, err
	}

	if opts.Disk {
		// temporary directory where all the gitleaks plain clones will reside
		dir, err = ioutil.TempDir("", "gitleaks")
		defer os.RemoveAll(dir)
		if err != nil {
			goto postAudit
		}
	}

	// start audits
	if opts.Repo != "" || opts.RepoPath != "" {
		repoInfo, err := newRepoInfo()
		if err != nil {
			goto postAudit
		}
		err = repoInfo.clone()
		if err != nil {
			goto postAudit
		}
		leaks, err = repoInfo.audit()
	} else if opts.OwnerPath != "" {
		repoDs, err := discoverRepos(opts.OwnerPath)
		if err != nil {
			goto postAudit
		}
		for _, repoInfo := range repoDs {
			err = repoInfo.clone()
			if err != nil {
				continue
			}
			leaksFromRepo, err := repoInfo.audit()

			if err != nil {
				log.Warnf("error occured auditing repo: %s, continuing", repoInfo.name)
			}
			leaks = append(leaksFromRepo, leaks...)
		}
	} else if opts.GithubOrg != "" || opts.GithubUser != "" {
		leaks, err = auditGithubRepos()
	} else if opts.GitLabOrg != "" || opts.GitLabUser != "" {
		leaks, err = auditGitlabRepos()
	} else if opts.GithubPR != "" {
		leaks, err = auditGithubPR()
	}

postAudit:
	if err != nil {
		if strings.Contains(err.Error(), "whitelisted") {
			log.Info(err.Error())
			os.Exit(0)
		}
		log.Error(err)
		os.Exit(ErrExit)
	}

	if opts.Report != "" {
		writeReport(leaks)
	}

	return &Report{
		Leaks:    leaks,
		Duration: durafmt.Parse(time.Now().Sub(now)).String(),
		Commits:  totalCommits,
	}, err
}
