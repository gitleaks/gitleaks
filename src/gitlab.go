package gitleaks

import (
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/xanzy/go-gitlab"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

// gitlabPages number of records per request
const gitlabPages = 100

// auditGitlabRepos kicks off audits if --gitlab-user or --gitlab-org options are set.
// Getting all repositories from the GitLab API and run audit. If an error occurs during an audit of a repo,
// that error is logged.
func auditGitlabRepos() (int, error) {
	var (
		ps      []*gitlab.Project
		resp    *gitlab.Response
		tempDir string
		err     error
		leaks   []Leak
	)

	repos := make([]*gitlab.Project, 0, gitlabPages)
	page := 1
	cl := gitlab.NewClient(nil, os.Getenv("GITLAB_TOKEN"))

	// if self hosted GitLab server
	if url := os.Getenv("GITLAB_URL"); url != "" {
		cl.SetBaseURL(url)
	}

	for {
		if opts.GitLabOrg != "" {
			opt := &gitlab.ListGroupProjectsOptions{
				ListOptions: gitlab.ListOptions{
					PerPage: gitlabPages,
					Page:    page,
				},
			}

			ps, resp, err = cl.Groups.ListGroupProjects(opts.GitLabOrg, opt)
		} else if opts.GitLabUser != "" {
			opt := &gitlab.ListProjectsOptions{
				ListOptions: gitlab.ListOptions{
					PerPage: gitlabPages,
					Page:    page,
				},
			}

			ps, resp, err = cl.Projects.ListUserProjects(opts.GitLabUser, opt)
		}

		if err != nil {
			// exit when can't make API call
			log.Fatal("error listing projects: ", err)
		}

		repos = append(repos, ps...)

		if page >= resp.TotalPages {
			// exit when we've seen all pages
			break
		}

		page = resp.NextPage
	}

	log.Debugf("found projects: %d", len(repos))

	if opts.Disk {
		if tempDir, err = createGitlabTempDir(); err != nil {
			log.Fatal("error creating temp directory: ", err)
		}
	}

	for _, p := range repos {
		repo, err := cloneGitlabRepo(tempDir, p)
		if err != nil {
			log.Warn(err)
			continue
		}

		err = repo.audit()
		if err != nil {
			log.Warn(err)
			continue
		}

		if opts.Disk {
			os.RemoveAll(fmt.Sprintf("%s/%d", tempDir, p.ID))
		}

		repo.report()
		leaks = append(leaks, repo.leaks...)
	}

	if opts.Report != "" {
		err = writeReport(leaks)
		if err != nil {
			return NoLeaks, err
		}
	}

	return len(leaks), nil
}

func createGitlabTempDir() (string, error) {
	pathName := opts.GitLabUser
	if opts.GitLabOrg != "" {
		pathName = opts.GitLabOrg
	}

	os.RemoveAll(fmt.Sprintf("%s/%s", dir, pathName))

	ownerDir, err := ioutil.TempDir(dir, pathName)
	if err != nil {
		return "", err
	}

	return ownerDir, nil
}

func cloneGitlabRepo(tempDir string, p *gitlab.Project) (*Repo, error) {
	var (
		repo *git.Repository
		err  error
	)
	if opts.ExcludeForks && p.ForkedFromProject != nil {
		return nil, fmt.Errorf("skipping %s, excluding forks", p.Name)
	}

	for _, re := range config.WhiteList.repos {
		if re.FindString(p.Name) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", p.Name)
		}
	}

	opt := &git.CloneOptions{
		URL: p.HTTPURLToRepo,
	}

	if config.sshAuth != nil {
		opt.URL = p.SSHURLToRepo
		opt.Auth = config.sshAuth
	}

	log.Infof("cloning: %s", p.Name)

	if opts.Disk {
		repo, err = git.PlainClone(fmt.Sprintf("%s/%d", tempDir, p.ID), false, opt)
	} else {
		repo, err = git.Clone(memory.NewStorage(), nil, opt)
	}

	if err != nil {
		return nil, err
	}

	return &Repo{
		repository: repo,
		name:       p.Name,
	}, nil
}
