package scan

import (
	"io/ioutil"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/zricethezav/gitleaks/v7/config"

	"github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
)

// ParentScanner is a parent directory scanner
type ParentScanner struct {
	cfg  config.Config
	opts options.Options
}

// NewParentScanner creates and returns a directory scanner
func NewParentScanner(opts options.Options, cfg config.Config) *ParentScanner {
	ds := &ParentScanner{
		opts: opts,
		cfg:  cfg,
	}
	return ds
}

// Scan kicks off a ParentScanner scan. This uses the directory from --path to discovery repos
func (ds *ParentScanner) Scan() (Report, error) {
	var scannerReport Report
	log.Debugf("scanning repos in %s\n", ds.opts.Path)

	files, err := ioutil.ReadDir(ds.opts.Path)
	if err != nil {
		return scannerReport, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		repo, err := git.PlainOpen(filepath.Join(ds.opts.Path, f.Name()))
		if err != nil {
			if err.Error() == "repository does not exist" {
				log.Debugf("%s is not a git repository", f.Name())
				continue
			}
			return scannerReport, err
		}
		if ds.cfg.Allowlist.RepoAllowed(f.Name()) {
			continue
		}

		if ds.opts.RepoConfigPath != "" {
			cfg, err := config.LoadRepoConfig(repo, ds.opts.RepoConfigPath)
			if err != nil {
				log.Warn(err)
			} else {
				ds.cfg = cfg
			}
		}

		rs := NewRepoScanner(ds.opts, ds.cfg, repo)
		rs.repoName = f.Name()
		repoReport, err := rs.Scan()
		if err != nil {
			return scannerReport, err
		}
		scannerReport.Leaks = append(scannerReport.Leaks, repoReport.Leaks...)
		scannerReport.Commits += repoReport.Commits
	}
	return scannerReport, nil
}
