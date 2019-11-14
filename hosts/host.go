package hosts

import (
	"github.com/zricethezav/gitleaks/manager"
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
	switch getHost(m.Opts.Host) {
	case _github:
		host = NewGithubClient(*m)
	case _gitlab:
		host = NewGitlabClient(*m)
	default:
		return nil
	}

	if m.Opts.PullRequest != "" {
		host.AuditPR()
	} else {
		host.Audit()
	}
	return nil
}

func getHost(host string) int {
	if strings.ToLower(host) == "github" {
		return _github
	} else if strings.ToLower(host) == "gitlab" {
		return _gitlab
	}
	return -1
}
