package cmd

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.AddCommand(stdInCmd)
}

var stdInCmd = &cobra.Command{
	Use:   "stdin",
	Short: "detect secrets from stdin",
	Run:   runStdIn,
}

func runStdIn(cmd *cobra.Command, args []string) {
	initConfig(".")
	var (
		findings []report.Finding
		err      error
	)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()
	detector := Detector(cmd, cfg, "")

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

	findings, err = detector.DetectReader(os.Stdin, 10)
	if err != nil {
		// log fatal to exit, no need to continue since a report
		// will not be generated when scanning from a pipe...for now
		log.Fatal().Err(err).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
