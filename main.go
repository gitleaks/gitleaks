package main

import (
	"os"
	"os/signal"
	"time"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"

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
	scannerReport, err := scanner.Scan()
	log.Info("scan time: ", durafmt.Parse(time.Now().Sub(start)))
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// report scan
	if err := scan.WriteReport(scannerReport, opts, cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	if len(scannerReport.Leaks) != 0 {
		os.Exit(opts.CodeOnLeak)
	}
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Warn("halting gitleaks scan")
	os.Exit(1)
}
