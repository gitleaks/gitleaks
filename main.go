package main

import (
	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks-ng/audit"
	"github.com/zricethezav/gitleaks-ng/config"
	"github.com/zricethezav/gitleaks-ng/hosts"
	"github.com/zricethezav/gitleaks-ng/manager"
	"github.com/zricethezav/gitleaks-ng/options"
	"io/ioutil"
	"os"
	"time"
)

// TODO documentation for
// 1. ./gitleaks-ng --repo=https://github.com/gitleakstest/gronit -v | jq -R 'fromjson?'
// 2. Dockerfile
// 3. need to add tests for --repo-config
// 4. look over comments and code
// 5. prepare release

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
		log.Warnf("%d leaks detected. %d commits audited in %s", len(leaks),
			metadata.Commits, durafmt.Parse(time.Duration(metadata.AuditTime)*time.Nanosecond))
		os.Exit(options.LeaksPresent)
	} else {
		log.Infof("No leaks detected. %d commits audited in %s",
			metadata.Commits, durafmt.Parse(time.Duration(metadata.AuditTime)*time.Nanosecond))
	}

	os.Exit(options.Success)
}

// Run begins the program and contains some basic logic on how to continue with the audit. If any external git host
// options are set (like auditing a gitlab or github user) then a specific host client will be created and
// then Audit() and Report() will be called. Otherwise, gitleaks will create a new repo and an audit will proceed.
// If no options or the uncommitted option is set then a pre-commit audit will
// take place -- this is similar to running `git diff` on all the tracked files.
// TODO handle errors from errChan
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
		err = audit.Run(m)
	}
	if err != nil {
		return err
	}

	return m.Report()
}
