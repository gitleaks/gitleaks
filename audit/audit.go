package audit

import (
	"fmt"
	"github.com/zricethezav/gitleaks-ng/manager"
	"io/ioutil"
	"path"
)

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
			m.Opts.RepoPath = fmt.Sprintf("%s/%s",m.Opts.OwnerPath, f.Name())
			if err := runHelper(NewRepo(m)); err != nil {
				// TODO or send to errchan?
				return err
			}
		}
		return nil
	}

	return runHelper(NewRepo(m))
}

func runHelper(r *Repo) error {
	// Check if gitleaks will perform a local audit.
	if r.Manager.Opts.OpenLocal() {
		r.Name = path.Base(r.Manager.Opts.RepoPath)
		if err := r.Open(); err != nil {
			return err
		}

		// Check if we are checking uncommitted files. This is the default behavior
		// for a "$gitleaks" command with no options set
		if r.Manager.Opts.CheckUncommitted() {
			if err := r.AuditLocal(); err != nil {
				return err
			}
			return nil
		}
	} else {
		if err := r.Clone(); err != nil {
			return err
		}
	}
	return r.Audit()
}

