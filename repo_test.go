package main

import (
	_ "fmt"
	"os"
	"testing"
)

func TestNewLocalRepo(t *testing.T) {
	r := newLocalRepo("")
	if r.path != "" {
		t.Error()
	}
	r = newLocalRepo("some/path")
	if r.name != "path" || r.path != "some/path" {
		t.Error()
	}
}

func TestWriteReport(t *testing.T) {
	opts, _ = defaultOptions()
	r := newRepo("fakerepo", "github.com", "")
	r.leaks = []Leak{*sampleLeak(), *sampleLeak()}
	r.writeReport(r.leaks)
	if _, err := os.Stat("fakerepo_leaks.json"); os.IsNotExist(err) {
		t.Error()
	} else {
		os.Remove("fakerepo_leaks.json")
	}
}

func TestAudit(t *testing.T) {
	opts, _ = defaultOptions()
	opts.RepoMode = true
	opts.Tmp = true
	opts.URL = "https://github.com/zricethezav/gronit"
	owner := newOwner()
	r := newRepo("gronit", opts.URL, owner.path)
	leaksPst, _ := r.audit()
	if !leaksPst {
		// TODO setup actual test repo
		t.Error()
	}

	// new owner
	opts.URL = "https://github.com/kelseyhightower/nocode"
	owner = newOwner()
	r = newRepo("nocode", opts.URL, owner.path)
	leaksPst, _ = r.audit()
	if leaksPst {
		t.Error()
	}
}

func sampleLeak() *Leak {
	return &Leak{
		Line:     "yoo",
		Commit:   "mycommit",
		Offender: "oh boy",
		Reason:   "hello",
		Msg:      "msg",
		Time:     "time",
		Author:   "lol",
		RepoURL:  "yooo",
	}
}
