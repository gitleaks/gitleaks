package main

import (
	"testing"
)

func TestCheckRegex(t *testing.T) {
	var results []LeakElem
	opts := &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
		Entropy:          false,
	}
	repo := RepoDesc{
		url: "someurl",
	}
	commit := Commit{}
	checks := map[string]int{
		"aws=\"AKIALALEMEL33243OLIAE": 1,
		"aws\"afewafewafewafewaf\"":   0,
	}

	for k, v := range checks {
		results = doChecks(k, commit, opts, repo)
		if v != len(results) {
			t.Errorf("regexCheck failed on string %s", k)
		}
	}
}

func TestEntropy(t *testing.T) {
	var enoughEntropy bool
	opts := &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
		Entropy:          false,
	}
	checks := map[string]bool{
		"reddit_api_secret = settings./.http}":           false,
		"heroku_client_secret = simple":                  false,
		"reddit_api_secret = \"4ok1WFf57-EMswEfAFGewa\"": true,
		"aws_secret= \"AKIAIMNOJVGFDXXFE4OA\"":           true,
	}
	for k, v := range checks {
		enoughEntropy = checkShannonEntropy(k, opts)
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
