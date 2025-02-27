package main

import (
	"os"
	"os/signal"

	"github.com/zricethezav/gitleaks/v8/cmd"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func main() {
	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	cmd.Execute()
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	logging.Fatal().Msg("Interrupt signal received. Exiting...")
}
