package cmd

import (
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
		if initErr := initConfig(source); initErr != nil {
			findings = nil
			err = initErr
		}
	})

	if err != nil {
		logging.Error().Err(err).Msg("Failed to initialize configuration")
		return findings, nil, err
	}

	// setup config (aka, the thing that defines rules)
	logging.Debug().Msgf("Initializing detector for source: %s", source)
	cfg := Config(cmd)
	detector := Detector(cmd, cfg, source)

	// set follow symlinks flag
	logging.Debug().Msg("Setting follow symlinks flag")
	detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks")
	if err != nil {
		logging.Error().Err(err).Msg("Failed to get follow-symlinks flag")
		return nil, nil, err
	}

	logging.Debug().Msg("Getting directory targets")
	var paths <-chan sources.ScanTarget
	paths, err = sources.DirectoryTargets(
		source,
		detector.Sema,
		detector.FollowSymlinks,
		detector.Config.Allowlist.PathAllowed,
	)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to get directory targets")
		return nil, nil, err
	}

	logging.Debug().Msg("Detecting files")
	findings, err = detector.DetectFiles(paths)
	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("Failed to detect files in directory")
	}

	return findings, detector, err
}
