package scan

import (
	"github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"path/filepath"
)

type DirScanner struct {
	BaseScanner

	leaks []Leak
}

func NewDirScanner(base BaseScanner) *DirScanner {
	ds := &DirScanner{
		BaseScanner: base,
	}
	ds.scannerType = TypeDirScanner
	return ds
}

func (ds *DirScanner) Scan() ([]Leak, error) {
	files, err := ioutil.ReadDir(ds.opts.OwnerPath)
	if err != nil {
		return ds.leaks, err
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
			return ds.leaks, err
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
		leaks, err:= rs.Scan()
		if err != nil {
			return ds.leaks, err
		}
		ds.leaks = append(ds.leaks, leaks...)
	}
	return ds.leaks, nil
}
