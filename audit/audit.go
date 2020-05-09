package audit

import (
	"fmt"
	"io/ioutil"
	"path"

	"github.com/zricethezav/gitleaks/v4/manager"

	log "github.com/sirupsen/logrus"
)

// Run accepts a manager and begins an audit based on the options/configs set in the manager.
func Run(m *manager.Manager) error {
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
			if err := runHelper(NewRepo(m)); err != nil {
				log.Warnf("%s is not a git repo, skipping", f.Name())
			}
		}
		return nil
	}

	return runHelper(NewRepo(m))
}

func runHelper(r *Repo) error {
	// Ignore whitelisted repos
	for _, wlRepo := range r.Manager.Config.Whitelist.Repos {
		if RegexMatched(r.Manager.Opts.RepoPath, wlRepo) {
			return nil
		}
		if RegexMatched(r.Manager.Opts.Repo, wlRepo) {
			return nil
		}
	}
	if r.Manager.Opts.OpenLocal() {
		r.Name = path.Base(r.Manager.Opts.RepoPath)
		if err := r.Open(); err != nil {
			return err
		}

		// Check if we are checking uncommitted files. This is the default behavior
		// for a "$ gitleaks" command with no options set
		if r.Manager.Opts.CheckUncommitted() {
			if err := r.AuditUncommitted(); err != nil {
				return err
			}
			return nil
		}
	} else {
		if err := r.Clone(nil); err != nil {
			return err
		}
	}
	return r.Audit()
}
