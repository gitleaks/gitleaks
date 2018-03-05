package main

import (
	"testing"
	"os"
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
	opts.ClonePath = "test"
	p, err = ownerPath("nameToIgnore")
	if p != "test" {
		t.Error()
	}
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
