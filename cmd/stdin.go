package cmd

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(stdInCmd)
}

var stdInCmd = &cobra.Command{
	Use:   "stdin",
	Short: "detect secrets from stdin",
	Run:   runStdIn,
}

func runStdIn(cmd *cobra.Command, _ []string) {
	// start timer
	start := time.Now()

	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, "")

	// parse flag(s)
	exitCode := mustGetIntFlag(cmd, "exit-code")

	findings, err := detector.DetectSource(
		context.Background(),
		&sources.File{
			Content:         os.Stdin,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	if err != nil {
		// log fatal to exit, no need to continue since a report will not be
		// generated when scanning from a pipe...for now
		logging.Fatal().Err(err).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
