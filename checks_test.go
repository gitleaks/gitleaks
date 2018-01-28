package main

import (
	"testing"
)

func TestCheckRegex(t *testing.T) {
	var secretsPresent bool
	checks := map[string]bool{
		"github.com":                         false,
		"github.com/user/":                   false,
		"github_api_client = \"sample key\"": true,
	}

	for k, v := range checks {
		_, secretsPresent = checkRegex(k)
		if v != secretsPresent {
			t.Errorf("regexCheck failed on string %s. Expected secretsPresent: %t, got %t", k, v, secretsPresent)
		}
	}
}
