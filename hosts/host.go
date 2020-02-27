package hosts

import (
	"github.com/zricethezav/gitleaks/v4/manager"
	"strings"
)

const (
	_github int = iota + 1
	_gitlab
)

// Host is an interface used for defining external git hosting providers like github and gitlab.
// TODO add bitbucket
type Host interface {
	Audit()
	AuditPR()
}

// Run kicks off a host audit. This function accepts a manager and determines what host it should audit
func Run(m *manager.Manager) error {
	var host Host
	var err error
	switch getHost(m.Opts.Host) {
	case _github:
		host, err = NewGithubClient(m)
	case _gitlab:
		host, err = NewGitlabClient(m)
	default:
		return nil
	}

	if m.Opts.PullRequest != "" {
		host.AuditPR()
	} else {
		host.Audit()
	}
	return err
}

func getHost(host string) int {
	if strings.ToLower(host) == "github" {
		return _github
	} else if strings.ToLower(host) == "gitlab" {
		return _gitlab
	}
	return -1
}
