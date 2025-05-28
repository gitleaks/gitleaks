package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	logOpts := mustGetStringFlag(cmd, "log-opts")
	staged := mustGetBoolFlag(cmd, "staged")
	preCommit := mustGetBoolFlag(cmd, "pre-commit")

	var (
		findings    []report.Finding
		err         error
		gitCmd      *sources.GitCmd
		scmPlatform scm.Platform
	)

	if preCommit || staged {
		if gitCmd, err = sources.NewGitDiffCmd(source, staged); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git diff cmd")
		}
		// Remote info + links are irrelevant for staged changes.
		scmPlatform = scm.NoPlatform
	} else {
		if gitCmd, err = sources.NewGitLogCmd(source, logOpts); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git log cmd")
		}
		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}
	}

	findings, err = detector.DetectSource(
		context.Background(),
		&sources.Git{
			Cmd:             gitCmd,
			Config:          &detector.Config,
			Remote:          sources.NewRemoteInfo(scmPlatform, source),
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
