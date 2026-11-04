package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
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
	Args:    cobra.MaximumNArgs(1),
	Run:     runDirectory,
}

// resolveDirSource returns the scan target from the positional arguments,
// defaulting to the current directory. It rejects extra arguments (e.g.
// `gitleaks dir detect file`, where `detect` is not a valid subcommand) and
// paths that do not exist instead of silently scanning the wrong target (#1979).
func resolveDirSource(args []string) (string, error) {
	if len(args) > 1 {
		return "", fmt.Errorf("expected at most one path argument, got %d", len(args))
	}
	source := "."
	if len(args) == 1 && args[0] != "" {
		source = args[0]
	}
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("invalid scan path %q: %w", source, err)
	}
	return source, nil
}

func runDirectory(cmd *cobra.Command, args []string) {
	// grab source
	source, err := resolveDirSource(args)
	if err != nil {
		logging.Fatal().Err(err).Send()
	}

	initConfig(source)
	initDiagnostics()

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	detector := Detector(cmd, cfg, source)

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		logging.Fatal().Err(err).Msg("could not get exit code")
	}

	findings, err := detector.DetectSource(
		cmd.Context(),
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

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
