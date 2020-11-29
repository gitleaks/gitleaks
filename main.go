package main

import (
	"encoding/json"
	"os"
	"os/signal"
	"time"

	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/options"
	"github.com/zricethezav/gitleaks/v6/scan"

	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
)

func main() {
	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	// setup options
	opts, err := options.ParseOptions()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	err = opts.Guard()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// setup configs
	cfg, err := config.NewConfig(opts)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// setup scanner
	scanner, err := scan.NewScanner(opts, cfg)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// run and time the scan
	start := time.Now()
	leaks, err := scanner.Scan()
	log.Info("scan time: ", durafmt.Parse(time.Now().Sub(start)))
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// report scan
	if err := report(leaks, opts); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func report(leaks []scan.Leak, opts options.Options) error {
	if len(leaks) != 0 {
		log.Warn("leaks found: ", len(leaks))
	} else {
		log.Info("leaks found: ", len(leaks))
	}
	if opts.Report != "" {
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
	}

	return nil
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Warn("halting gitleaks scan")
	os.Exit(1)
}
