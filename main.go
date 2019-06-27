package main

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	gitleaks "github.com/zricethezav/gitleaks/src"
)

func main() {
	err := gitleaks.Run(gitleaks.ParseOpts())
	if err != nil {
		if strings.Contains(err.Error(), "whitelisted") {
			log.Info(err.Error())
			os.Exit(0)
		}
		log.Error(err)
		os.Exit(gitleaks.ErrExit)
	}
}
