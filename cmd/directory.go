package cmd

import (
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
	if err = initConfig(source); err != nil {
		return findings, nil, err
	}

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)
	detector := Detector(cmd, cfg, source)

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		return nil, nil, err
	}

	var paths <-chan sources.ScanTarget
	paths, err = sources.DirectoryTargets(
		source,
		detector.Sema,
		detector.FollowSymlinks,
		detector.Config.Allowlist.PathAllowed,
	)
	if err != nil {
		return nil, nil, err
	}

	findings, err = detector.DetectFiles(paths)
	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed scan directory")
	}

	return findings, detector, err
}
