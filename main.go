package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/zricethezav/gitleaks/v8/cmd"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func main() {
	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			logging.Error().Msg("Interrupt signal received. Exiting...")
			cancel()
		case <-ctx.Done():
			return
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	cmd.Execute(ctx)
}
