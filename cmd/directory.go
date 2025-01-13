package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(directoryCmd)
	directoryCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
}

var directoryCmd = &cobra.Command{
	Use:     "dir [flags] [path]",
	Aliases: []string{"file", "directory"},
	Short:   "scan directories or files for secrets",
	Run:     runDirectory,
}

func runDirectory(cmd *cobra.Command, args []string) {
	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}
	initConfig(source)
	var (
		findings []report.Finding
		err      error
	)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	detector := Detector(cmd, cfg, source)

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		logging.Fatal().Err(err).Msg("")
	}
	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		logging.Fatal().Err(err).Msg("could not get exit code")
	}

	var paths <-chan sources.ScanTarget
	paths, err = sources.DirectoryTargets(
		source,
		detector.Sema,
		detector.FollowSymlinks,
		detector.Config.Allowlist.PathAllowed,
	)
	if err != nil {
		logging.Fatal().Err(err)
	}

	findings, err = detector.DetectFiles(paths)
	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed scan directory")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
