package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/src"
)

func main() {
	report, err := gitleaks.Run(gitleaks.ParseOpts())
	if err != nil {
		log.Fatal(err)
	}

	if len(report.Leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
		os.Exit(gitleaks.LeakExit)
	} else {
		log.Infof("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
	}
}
