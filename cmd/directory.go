package cmd

import (
	"context"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
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

var (
	initConfigOnce sync.Once
)

func runDirectory(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		args = append(args, ".") // Default to current directory if no args are provided
	}

	var (
		start = time.Now()

		detector    *detect.Detector
		err         error
		allFindings []report.Finding
	)
	for _, arg := range args {
		findings, d, scanErr := runDirectoryScan(cmd, arg)
		if scanErr != nil {
			logging.Err(scanErr).
				Str("path", arg).
				Msg("failed scan path")
			err = scanErr
		}
		if detector == nil {
			detector = d
		}

		allFindings = append(allFindings, findings...)

	}

	exitCode, exitCodeErr := cmd.Flags().GetInt("exit-code")
	if exitCodeErr != nil {
		logging.Fatal().Err(exitCodeErr).Msg("could not get exit code")
	}

	findingSummaryAndExit(detector, allFindings, exitCode, start, err)
}

func runDirectoryScan(cmd *cobra.Command, source string) ([]report.Finding, *detect.Detector, error) {
	var (
		findings []report.Finding
		err      error
	)

	logging.Debug().Msg("Initializing configuration")
	initConfigOnce.Do(func() {
		initConfig(source)
		initDiagnostics()
	})

	// setup config (aka, the thing that defines rules)
	logging.Debug().Msgf("Initializing detector for source: %s", source)
	cfg := Config(cmd)
	detector := Detector(cmd, cfg, source)

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	findings, err = detector.DetectSource(
		context.Background(),
		&sources.Files{
			Config:          &cfg,
			FollowSymlinks:  detector.FollowSymlinks,
			MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
			Path:            source,
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	if err != nil {
		logging.Error().Err(err).Msg("failed scan directory")
	}

	return findings, detector, err
}
