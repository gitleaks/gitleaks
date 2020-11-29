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

func (ds *DirScanner) Scan() ([]Leak, error) {
	files, err := ioutil.ReadDir(ds.opts.OwnerPath)
	if err != nil {
		return ds.leaks, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		repo, err := getRepo(ds.opts)
		if err != nil {
			return ds.leaks, err
		}
		rs := NewRepoScanner(ds.BaseScanner, repo)
		leaks, err:= rs.Scan()
		if err != nil {
			return ds.leaks, err
		}
		ds.leaks = append(ds.leaks, leaks...)
	}
	return ds.leaks, nil
}
