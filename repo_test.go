package main

import (
	"testing"
	"os"
	"fmt"
)

func TestNewRepo(t *testing.T) {
	// TODO
}

func TestNewLocalRepo(t *testing.T) {
	// TODO
}

func TestWriteReport(t *testing.T) {
	opts, _ = defaultOptions()
	r := newRepo("fakerepo", "github.com", "")
	r.leaks = []Leak{*sampleLeak(), *sampleLeak()}
	r.writeReport()
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
	r := newRepo("gronit", "https://github.com/zricethezav/gronit", owner.path)
	r.audit()

}

func sampleLeak() *Leak {
	return &Leak{
		Line: "yoo",
		Commit: "mycommit",
		Offender: "oh boy",
		Reason: "hello",
		Msg: "msg",
		Time: "time",
		Author: "lol",
		RepoURL: "yooo",
	}
}
