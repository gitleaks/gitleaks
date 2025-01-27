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
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/detect"
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
	source := mustGetStringFlag(cmd, "source")

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	detector.FollowSymlinks = mustGetBoolFlag(cmd, "follow-symlinks")
	exitCode := mustGetIntFlag(cmd, "exit-code")
	noGit := mustGetBoolFlag(cmd, "no-git")
	fromPipe := mustGetBoolFlag(cmd, "pipe")

	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	var (
		findings []report.Finding
		err      error
	)
	if noGit {
		paths, err := sources.DirectoryTargets(
			source,
			detector.Sema,
			detector.FollowSymlinks,
			detector.Config.Allowlist.PathAllowed,
		)
		if err != nil {
			logging.Fatal().Err(err).Send()
		}

		if findings, err = detector.DetectFiles(paths); err != nil {
			// don't exit on error, just log it
			logging.Error().Err(err).Msg("failed scan directory")
		}
	} else if fromPipe {
		if findings, err = detector.DetectReader(os.Stdin, 10); err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			logging.Fatal().Err(err).Msg("failed scan input from stdin")
		}
	} else {
		var (
			logOpts     = mustGetStringFlag(cmd, "log-opts")
			gitCmd      *sources.GitCmd
			scmPlatform scm.Platform
			remote      *detect.RemoteInfo
		)
		if gitCmd, err = sources.NewGitLogCmd(source, logOpts); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git cmd")
		}
		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}
		if remote, err = detect.NewRemoteInfo(scmPlatform, source); err != nil {
			logging.Fatal().Err(err).Msg("failed to scan Git repository")
		}

		if findings, err = detector.DetectGit(gitCmd, remote); err != nil {
			// don't exit on error, just log it
			logging.Error().Err(err).Msg("failed to scan Git repository")
		}
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
