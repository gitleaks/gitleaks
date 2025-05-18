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
	"iter"

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
	var (
		source     sources.Source
		sourceKind string
	)

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

	if noGit {
		// no-git: create a source to scan a directory
		sourceKind = "directory"
		source := &sources.Files {
			Config: detector.Config,
			FollowSymlinks: detector.FollowSymlinks,
			Path: sourcePath,
			Sema: detector.Sema,
			MaxTargetMegaBytes: detector.MaxTargetMegaBytes,
		}
	} else if fromPipe {
		// pipe: create a source to scan stdin
		sourceKind = "pipe"
		source = &sources.Pipe {
			Reader: os.Stdin
		}
	}else {
		// git: create a source to scan the history of a git repo
		sourceKind = "git"
		if scmPlatform, err := scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}
		source = &sources.Git {
			LogOpts: mustGetStringFlag(cmd, "log-opts"),
			Platform scmPlatform,
		}
	}

	// scan the fragments and generate findings
	if findings, err := detector.DetectFragments(source.Fragments()); err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msgf("failed %s scan", sourceKind)
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
