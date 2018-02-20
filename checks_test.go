package main

import (
	"testing"
)

func TestCheckRegex(t *testing.T) {
	var results []string
	checks := map[string]int{
		"github.com":                                                                                     0,
		"github.com/user/":                                                                               0,
		"github.com/user -- Sys":                                                                         0,
		"github_api_client = \"sample key\"\naws=afewafewafewafewaf":                                     2,
		"aws=\"afewafewafewafewaf\"":                                                                     1,
		"aws\"afewafewafewafewaf\"":                                                                      0,
		"heroku := \"afewafewafewafewaf\"":                                                               1,
		"heroku_client_secret := \"afewafewafewafewaf\"":                                                 1,
		"reddit_api_secreit = \"Fwe4fa431FgklreF\"":                                                      1,
		"+ * [Github Help: Managing Deploy Keys](https://help.github.com/articles/managing-deploy-keys)": 0,
	}

	for k, v := range checks {
		results = checkRegex(k)
		if v != len(results) {
			t.Errorf("regexCheck failed on string %s", k)
		}
	}
}

func TestEntropy(t *testing.T) {
	var enoughEntropy bool
	checks := map[string]bool{
		"reddit_api_secret = settings./.http}":           false,
		"heroku_client_secret = simple":                  false,
		"reddit_api_secret = \"4ok1WFf57-EMswEfAFGewa\"": true,
		"aws_secret= \"AKIAIMNOJVGFDXXFE4OA\"":           true,
	}
	for k, v := range checks {
		enoughEntropy = checkShannonEntropy(k, 70, 40)
		if v != enoughEntropy {
			t.Errorf("checkEntropy failed for %s. Expected %t, got %t", k, v, enoughEntropy)
		}
	}

}

func TestStopWords(t *testing.T) {
	if containsStopWords("aws_secret=settings.AWS_SECRET") != true {
		t.Errorf("checkStopWords Failed")
	}
}
