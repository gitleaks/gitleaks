package scan

import (
	"io/ioutil"
)

type DirScanner struct {
	BaseScanner

	leaks []Leak
}

func NewDirScanner(base BaseScanner) *DirScanner {
	return &DirScanner{
		BaseScanner: base,
	}
}

func (ds *DirScanner) Scan() error {
	files, err := ioutil.ReadDir(ds.opts.OwnerPath)
	if err != nil {
		return err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		repo, err := getRepo(ds.opts)
		if err != nil {
			return err
		}
		rs := NewRepoScanner(ds.BaseScanner, repo)
		if err := rs.Scan(); err != nil {
			return err
		}
		ds.leaks = append(ds.leaks, rs.GetLeaks()...)
	}
	return nil
}

func (ds *DirScanner) GetLeaks() []Leak {
	return ds.leaks
}
