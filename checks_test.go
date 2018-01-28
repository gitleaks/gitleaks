package main

import (
	"testing"
)

func TestCheckRegex(t *testing.T) {
	var secretsPresent bool
	var results []string
	checks := map[string]bool{
		"github.com":                                     false,
		"github.com/user/":                               false,
		"github_api_client = \"sample key\"":             true,
		"aws=\"afewafewafewafewaf\"":                     true,
		"aws\"afewafewafewafewaf\"":                      false,
		"heroku := \"afewafewafewafewaf\"":               true,
		"heroku_client_secret := \"afewafewafewafewaf\"": true,
		"reddit_api_secreit = \"Fwe4fa431FgklreF\"":      true,
	}

	for k, v := range checks {
		results, secretsPresent = checkRegex(k)
		if v != secretsPresent {
			t.Errorf("regexCheck failed on string %s. Expected secretsPresent: %t, got %t, %v", k, v, secretsPresent, results)
		}
	}
}
