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
		"github.com/user -- Sys":                         false,
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

func TestEntropy(t *testing.T) {
	var enoughEntropy bool
	checks := map[string]bool{
		"heroku_client_secret = settings.HEROKU_CLIENT": false,
		"heroku_client_secret = conf.heroku":            false,
		"reddit_secret = settings.REDDIT_API":           false,
		"reddit_api_secret = \"Fwe4fa431FgklreF\"":      true,
		"aws_secret= \"AKIAIMNOJVGFDXXXE4OA\"":          true,
	}
	for k, v := range checks {
		enoughEntropy = checkEntropy(k)
		if v != enoughEntropy {
			t.Errorf("checkEntropy failed for %s. Expected %t, got %t", k, v, enoughEntropy)
		}
	}

}
