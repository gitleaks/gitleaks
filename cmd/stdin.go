package cmd

import (
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

	stdin := &sources.File{
		Content:   os.Stdin,
		ChunkSize: 10000,
	}

	findings, err := detector.DetectSource(stdin)
	if err != nil {
		logging.Fatal().Err(err).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
