package main

import (
	"testing"
)

func TestNextInt(t *testing.T) {
	args := []string{"-c", "10"}
	i := 0
	opts, err := defaultOptions()
	if err != nil {
		t.Error()
	}
	n := opts.nextInt(args, &i)
	if n != 10 {
		t.Error()
	}
}

func TestNextString(t *testing.T) {
	args := []string{"--fake", "flag"}
	i := 0
	opts, err := defaultOptions()
	if err != nil {
		t.Error()
	}
	n := opts.nextString(args, &i)
	if n != "flag" {
		t.Error()
	}
}

func TestOptString(t *testing.T) {
	opts, err := defaultOptions()
	if err != nil {
		t.Error()
	}
	match, n := opts.optString("--fake=flag", "--fake=")
	if !match || n != "flag" {
		t.Error()
	}
}

func TestOptInt(t *testing.T) {
	opts, err := defaultOptions()
	if err != nil {
		t.Error()
	}
	match, n := opts.optInt("--fake=10", "--fake=")
	if !match || n != 10 {
		t.Error()
	}
}

func TestParseOptions(t *testing.T) {
	opts, err := defaultOptions()
	opts.URL = "github.com/sample"
	if err != nil {
		t.Error()
	}
	opts.RepoMode = false
	opts.UserMode = true
	opts.LocalMode = true
	err = opts.guards()
	if err == nil {
		t.Error()
	}

	opts.RepoMode = true
	opts.UserMode = false
	opts.LocalMode = false
	err = opts.guards()
	if err != nil {
		t.Error()
	}
}

func TestGithubTarget(t *testing.T) {
	if !isGithubTarget("github.com") {
		t.Error()
	}
	if !isGithubTarget("https://github.com/") {
		t.Error()
	}
	if !isGithubTarget("git@github.com:zricethezav/gitleaks.git") {
		t.Error()
	}
}
