package main

import (
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
	flag.Parse()

	if *concurrency < 1 {
		*concurrency = 1
	}

	if *userURL == "" && *repoURL == "" && *orgURL == "" {
		log.Fatal("No repository specified")
	}
}