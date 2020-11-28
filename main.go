package main

import (
	"encoding/json"
	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
	"github.com/zricethezav/gitleaks/v6/scan"
	"os"

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

	// report scan
	if err := report(scanner, opts); err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}
}

func report(scanner scan.Scanner, opts options.Options) error {
	leaks := scanner.GetLeaks()
	file, err := os.Create(opts.Report)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", " ")
	err = encoder.Encode(leaks)
	if err != nil {
		return err
	}
	return nil
}
