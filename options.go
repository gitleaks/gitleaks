package main

import (
	"regexp"
	"fmt"
	"log"
	"flag"
)

var (
	concurrency      = flag.Int("c", 10, "Concurrency factor (potential number of git files open)")
	b64EntropyCutoff = flag.Int("e", 70, "Base64 entropy cutoff")
	hexEntropyCutoff = flag.Int("x", 40, "Hex entropy cutoff")
	userURL          = flag.String("u", "", "Git user URL")
	repoURL          = flag.String("r", "", "Git repo URL")
	orgURL           = flag.String("o", "", "Git organization URL")
	strict           = flag.Bool("s", false, "Strict mode uses stopwords in checks.go")
)

func parseOptions() {
	flag.Usage = usage
	flag.Parse()

	if *concurrency < 1 {
		*concurrency = 1
	}

	if *userURL == "" && *repoURL == "" && *orgURL == "" {
		if flag.NArg() != 0 && isGithubURL(flag.Arg(0)) {
			*repoURL = flag.Arg(0)
		} else {
			flag.Usage()
			log.Fatal("No repository specified")
		}
	}

	if *userURL != "" && !isGithubURL(*userURL) {
		flag.Usage()
		log.Fatalf("%s is not a valid URL!", userURL)
	}

	if *orgURL != "" && !isGithubURL(*orgURL) {
		flag.Usage()
		log.Fatalf("%s is not a valid URL!", orgURL)
	}

	if *repoURL != "" && !isGithubURL(*repoURL) {
		flag.Usage()
		log.Fatalf("%s is not a valid URL!", repoURL)
	}
}

func isGithubURL(url string) bool {
	re := regexp.MustCompile("^https?:\\/\\/github\\.com\\/")
	return re.MatchString(url)
}

func usage() {
	// https://stackoverflow.com/questions/31873183/how-to-print-usage-for-positional-argument-with-gos-flag-package
	fmt.Print("Usage: gitleaks [options] [git url]\n\nOptions:\n")
	flag.PrintDefaults()
}