package main

import "testing"

func TestNewRepo(t *testing.T) {
	// TODO
}

func TestNewLocalRepo(t *testing.T) {
	// TODO
}

func TestWriteReport(t *testing.T) {
	// TODO
	opts, err := defaultOptions()
	r := newRepo("fakerepo", "github.com")
	sampleLeak := Leak{
		Line: "yoo",
		Commit: "mycommit",
		Offender: "oh boy",
		Reason: "hello",
		Msg: "msg",
		Time: "time",
		Author: "lol",
		RepoURL: "yooo",
	}
	r.leaks = []Leak{sampleLeak, sampleLeak}
	r.writeReport()
}
