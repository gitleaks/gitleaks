package scan

import (
	"io/ioutil"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v7/report"

	"github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
)

type DirScanner struct {
	BaseScanner
}

func NewDirScanner(base BaseScanner) *DirScanner {
	ds := &DirScanner{
		BaseScanner: base,
	}
	ds.scannerType = TypeDirScanner
	return ds
}

func (ds *DirScanner) Scan() (report.Report, error) {
	var scannerReport report.Report
	log.Debugf("scanning repos in %s\n", ds.opts.OwnerPath)

	files, err := ioutil.ReadDir(ds.opts.OwnerPath)
	if err != nil {
		return scannerReport, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		repo, err := git.PlainOpen(filepath.Join(ds.opts.OwnerPath, f.Name()))
		if err != nil {
			if err.Error() == "repository does not exist" {
				log.Debugf("%s is not a git repository", f.Name())
				continue
			}
			return scannerReport, err
		}
		skip := false
		for _, allowListedRepo := range ds.cfg.Allowlist.Repos {
			if regexMatched(f.Name(), allowListedRepo) {
				skip = true
			}
		}
		if skip {
			continue
		}

		rs := NewRepoScanner(ds.BaseScanner, repo)
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
