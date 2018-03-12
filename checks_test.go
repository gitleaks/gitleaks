package main

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

func TestCheckRegex(t *testing.T) {
	var results []Leak
	opts = &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
		Entropy:          false,
	}
	repo := Repo{
		url: "someurl",
	}
	commit := Commit{}
	checks := map[string]int{
		"aws=\"AKIALALEMEL33243OLIAE": 1,
		"aws\"afewafewafewafewaf\"":   0,
	}

	for k, v := range checks {
		results = doChecks(k, commit, &repo)
		if v != len(results) {
			t.Errorf("regexCheck failed on string %s", k)
		}
	}
}

func TestExternalRegex(t *testing.T) {
	opts, err := defaultOptions()
	if err != nil {
		t.Error()
	}
	file, err := os.Create("testregex.txt")
	if err != nil {
		t.Error()
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, "AKIA[0-9A-Z]{16}")
	w.Flush()

	opts.RegexFile = "testregex.txt"
	opts.loadExternalRegex()
	leaks := doChecks("aws=\"AKIALALEMEL33243OLIAE",
		Commit{}, &Repo{url: "someurl"})
	if len(leaks) != 2 {
		// leak from default regex, leak from external
		t.Error()
	}
	os.Remove("testregex.txt")
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
