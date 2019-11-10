package hosts

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
	"github.com/zricethezav/gitleaks/audit"
	"github.com/zricethezav/gitleaks/manager"
	"github.com/zricethezav/gitleaks/options"
	"sync"
)

type GitlabError struct {
	Err    string
	Repo   string
	Commit string
}

func (gitlabError *GitlabError) Error() string {
	return fmt.Sprintf("repo: %s, err: %s",
		gitlabError.Repo, gitlabError.Err)
}

type Gitlab struct {
	client  *gitlab.Client
	errChan chan GitlabError
	manager manager.Manager
	ctx     context.Context
	wg      sync.WaitGroup
}

func NewGitlabClient(m manager.Manager) *Gitlab {
	return &Gitlab{
		manager: m,
		ctx:     context.Background(),
		client:  gitlab.NewClient(nil, options.GetAccessToken(m.Opts)),
		errChan: make(chan GitlabError),
	}
}

// Audit will audit a github user or organization's repos.
func (g *Gitlab) Audit() {
	var (
		projects []*gitlab.Project
		resp     *gitlab.Response
		err      error
	)

	page := 1
	listOpts := gitlab.ListOptions{
		PerPage: 100,
		Page:    page,
	}
	for {
		var _projects []*gitlab.Project
		if g.manager.Opts.User != "" {
			glOpts := &gitlab.ListProjectsOptions{
				ListOptions: listOpts,
			}
			projects, resp, err = g.client.Projects.ListUserProjects(g.manager.Opts.User, glOpts)

		} else if g.manager.Opts.Organization != "" {
			glOpts := &gitlab.ListGroupProjectsOptions{
				ListOptions: listOpts,
			}
			projects, resp, err = g.client.Groups.ListGroupProjects(g.manager.Opts.Organization, glOpts)
		}
		if err != nil {
			log.Error(err)
		}

		projects = append(projects, _projects...)
		if resp == nil {
			break
		}
		if page >= resp.TotalPages {
			// exit when we've seen all pages
			break
		}
		page = resp.NextPage
	}

	// iterate of gitlab projects
	for _, p := range projects {
		r := audit.NewRepo(&g.manager)
		cloneOpts := g.manager.CloneOptions
		cloneOpts.URL = p.HTTPURLToRepo
		err := r.Clone(cloneOpts)
		r.Name = p.Name

		if err = r.Audit(); err != nil {
			log.Error(err)
		}
	}
}

// Audit(MR)PR TODO
func (g *Gitlab) AuditPR() {
	log.Error("AuditPR is not implemented in Gitlab host yet...")
}
