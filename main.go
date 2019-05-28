package main

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	gitleaks "github.com/zricethezav/gitleaks/src"
)

func main() {
	report, err := gitleaks.Run(gitleaks.ParseOpts())
	if err != nil {
		if strings.Contains(err.Error(), "whitelisted") {
			log.Info(err.Error())
			os.Exit(0)
		}
		log.Error(err)
		os.Exit(gitleaks.ErrExit)
	}

	if len(report.Leaks) != 0 {
		log.Warnf("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
		os.Exit(gitleaks.LeakExit)
	} else {
		log.Infof("%d leaks detected. %d commits inspected in %s", len(report.Leaks), report.Commits, report.Duration)
	}
}
