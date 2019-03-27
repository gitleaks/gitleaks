package gitleaks

import (
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/github"
	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
)

// Leak represents a leaked secret or regex match.
type Leak struct {
	Line     string    `json:"line"`
	Commit   string    `json:"commit"`
	Offender string    `json:"offender"`
	Type     string    `json:"reason"`
	Message  string    `json:"commitMsg"`
	Author   string    `json:"author"`
	File     string    `json:"file"`
	Repo     string    `json:"repo"`
	Date     time.Time `json:"date"`
}

type gitDiff struct {
	content      string
	commit       *object.Commit
	filePath     string
	repoName     string
	githubCommit *github.RepositoryCommit
	sha          string
	message      string
	author       string
	date         time.Time
}

var (
	opts              *Options
	config            *Config
	singleSearchRegex *regexp.Regexp
	dir               string
	threads           int
	totalCommits      int64
	commitMap         = make(map[string]bool)
	cMutex            = &sync.Mutex{}
	auditDone         bool
)

func init() {
	log.SetOutput(os.Stdout)
	threads = defaultThreadNum
}

// Run is the entry point for gitleaks
func Run() {
	var (
		leaks []Leak
		err   error
	)
	opts, err = setupOpts()
	if err != nil {
		log.Fatal(err)
	}
	config, err = newConfig()
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()

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
		repoD, err := newRepoD()
		if err != nil {
			goto postAudit
		}
		err = repoD.clone()
		if err != nil {
			goto postAudit
		}
		leaks, err = repoD.audit()
	} else if opts.OwnerPath != "" {
		repoDs, err := discoverRepos(opts.OwnerPath)
		if err != nil {
			goto postAudit
		}
		for _, repoD := range repoDs {
			err = repoD.clone()
			if err != nil {
				continue
			}
			leaksFromRepo, err := repoD.audit()

			if err != nil {
				log.Warnf("error occured auditing repo: %s, continuing", repoD.name)
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
		os.Exit(errExit)
	}

	if opts.Report != "" {
		writeReport(leaks)
	}

	if len(leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(leaks), totalCommits, durafmt.Parse(time.Now().Sub(now)).String())
		os.Exit(leakExit)
	} else {
		log.Infof("%d leaks detected. %d commits inspected in %s", len(leaks), totalCommits, durafmt.Parse(time.Now().Sub(now)).String())
	}
}
