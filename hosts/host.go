package hosts

import (
	"strings"

	"github.com/zricethezav/gitleaks/v5/manager"
)

const (
	_github int = iota + 1
	_gitlab
)

// Host is an interface used for defining external git hosting providers like github and gitlab.
// TODO add bitbucket
type Host interface {
	Scan()
	ScanPR()
}

// Run kicks off a host scan. This function accepts a manager and determines what host it should scan
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

	if err != nil {
		return err
	}

	if m.Opts.PullRequest != "" {
		host.ScanPR()
	} else {
		host.Scan()
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
