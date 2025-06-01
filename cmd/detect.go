// The `detect` and `protect` command is now deprecated. Here are some equivalent commands
// to help guide you.

// OLD CMD: gitleaks detect --source={repo}
// NEW CMD: gitleaks git {repo}

// OLD CMD: gitleaks protect --source={repo}
// NEW CMD: gitleaks git --pre-commit {repo}

// OLD  CMD: gitleaks protect --staged --source={repo}
// NEW CMD: gitleaks git --pre-commit --staged {repo}

// OLD CMD: gitleaks detect --no-git --source={repo}
// NEW CMD: gitleaks directory {directory/file}

// OLD CMD: gitleaks detect --no-git --pipe
// NEW CMD: gitleaks stdin

package cmd

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringP("source", "s", ".", "path to source")
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
}

var detectCmd = &cobra.Command{
	Use:    "detect",
	Short:  "detect secrets in code",
	Run:    runDetect,
	Hidden: true,
}

func runDetect(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()
	sourcePath := mustGetStringFlag(cmd, "source")

	// setup config (aka, the thing that defines rules)
	initConfig(sourcePath)
	initDiagnostics()
	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, sourcePath)

	// parse flags
	detector.FollowSymlinks = mustGetBoolFlag(cmd, "follow-symlinks")
	exitCode := mustGetIntFlag(cmd, "exit-code")
	noGit := mustGetBoolFlag(cmd, "no-git")
	fromPipe := mustGetBoolFlag(cmd, "pipe")

	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	var (
		err      error
		findings []report.Finding
		ctx      = context.Background()
	)
	if noGit {
		findings, err = detector.DetectSource(
			ctx, &sources.Files{
				Config:          &cfg,
				FollowSymlinks:  detector.FollowSymlinks,
				MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
				Path:            sourcePath,
				Sema:            detector.Sema,
				MaxArchiveDepth: detector.MaxArchiveDepth,
			},
		)

		if err != nil {
			// don't exit on error, just log it
			logging.Error().Err(err).Msg("failed to scan directory")
		}
	} else if fromPipe {
		findings, err = detector.DetectSource(
			ctx, &sources.File{
				Content:         os.Stdin,
				MaxArchiveDepth: detector.MaxArchiveDepth,
			},
		)

		if err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			logging.Fatal().Err(err).Msg("failed scan input from stdin")
		}
	} else {
		var (
			gitCmd      *sources.GitCmd
			scmPlatform scm.Platform
		)

		logOpts := mustGetStringFlag(cmd, "log-opts")
		if gitCmd, err = sources.NewGitLogCmd(sourcePath, logOpts); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git cmd")
		}

		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}

		findings, err = detector.DetectSource(
			ctx, &sources.Git{
				Cmd:             gitCmd,
				Config:          &detector.Config,
				Remote:          sources.NewRemoteInfo(scmPlatform, sourcePath),
				Sema:            detector.Sema,
				MaxArchiveDepth: detector.MaxArchiveDepth,
			},
		)

		if err != nil {
			// don't exit on error, just log it
			logging.Error().Err(err).Msg("failed to scan Git repository")
		}
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
