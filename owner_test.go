package main

import (
	"os"
	"testing"
)

func TestOwnerPath(t *testing.T) {
	opts, _ = defaultOptions()
	p, err := ownerPath("testName")
	if err != nil {
		t.Error()
	}
	pwd, _ := os.Getwd()
	if pwd != p {
		t.Error()
	}
	opts.ClonePath = "gitleaksTestClonePath"
	p, err = ownerPath("nameToIgnore")
	if p != "gitleaksTestClonePath" {
		t.Error()
	}
	os.Remove("gitleaksTestClonePath")
}

func TestNewOwner(t *testing.T) {
	opts, _ = defaultOptions()
	owner := newOwner()

	// default options will assume gitleaks is
	// running on local mode
	pwd, _ := os.Getwd()
	if pwd != owner.path {
		t.Error()
	}
}
