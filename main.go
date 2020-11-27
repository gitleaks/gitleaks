package main

import (
	"fmt"
	"os"

	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
	"github.com/zricethezav/gitleaks/v6/scan"

	log "github.com/sirupsen/logrus"
)

func main() {
	// setup options
	opts, err := options.ParseOptions()
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	err = opts.Guard()
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	// setup configs
	cfg, err := config.NewConfig(opts)
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	// setup scanner
	scanner, err := scan.NewScanner(opts, cfg)
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	// run scan
	if err := scanner.Scan(); err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	report(scanner)
}

func report(scanner scan.Scanner) {
	leaks := scanner.GetLeaks()
	fmt.Print(leaks)
}
