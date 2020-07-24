package main

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/zricethezav/gitleaks/v5/config"
	"github.com/zricethezav/gitleaks/v5/hosts"
	"github.com/zricethezav/gitleaks/v5/manager"
	"github.com/zricethezav/gitleaks/v5/options"
	"github.com/zricethezav/gitleaks/v5/scan"

	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
)

func main() {
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

	cfg, err := config.NewConfig(opts)
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	m, err := manager.NewManager(opts, cfg)
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	err = Run(m)
	if err != nil {
		log.Error(err)
		os.Exit(options.ErrorEncountered)
	}

	leaks := m.GetLeaks()
	metadata := m.GetMetadata()

	if len(m.GetLeaks()) != 0 {
		if m.Opts.CheckUncommitted() {
			log.Warnf("%d leaks detected in staged changes", len(leaks))
		} else {
			log.Warnf("%d leaks detected. %d commits scanned in %s", len(leaks),
				metadata.Commits, durafmt.Parse(time.Duration(metadata.ScanTime)*time.Nanosecond))
		}
		os.Exit(options.LeaksPresent)
	} else {
		if m.Opts.CheckUncommitted() {
			log.Infof("No leaks detected in staged changes")
		} else {
			log.Infof("No leaks detected. %d commits scanned in %s",
				metadata.Commits, durafmt.Parse(time.Duration(metadata.ScanTime)*time.Nanosecond))
		}
		os.Exit(options.Success)
	}
}

// Run begins the program and contains some basic logic on how to continue with the scan. If any external git host
// options are set (like scanning a gitlab or github user) then a specific host client will be created and
// then Scan() and Report() will be called. Otherwise, gitleaks will create a new repo and an scan will proceed.
// If no options or the uncommitted option is set then a pre-commit scan will
// take place -- this is similar to running `git diff` on all the tracked files.
func Run(m *manager.Manager) error {
	if m.Opts.Disk {
		dir, err := ioutil.TempDir("", "gitleaks")
		defer os.RemoveAll(dir)
		if err != nil {
			return err
		}
		m.CloneDir = dir
	}

	var err error
	if m.Opts.Host != "" {
		err = hosts.Run(m)
	} else {
		err = scan.Run(m)
	}
	if err != nil {
		return err
	}

	return m.Report()
}
