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

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

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
}

var detectCmd = &cobra.Command{
	Use:    "detect",
	Short:  "detect secrets in code",
	Run:    runDetect,
	Hidden: true,
}

func runDetect(cmd *cobra.Command, args []string) {
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get source")
	}
	initConfig(source)

	var findings []report.Finding

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	detector := Detector(cmd, cfg, source)

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	noGit, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
	}
	fromPipe, err := cmd.Flags().GetBool("pipe")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for pipe")
	}

	// start the detector scan
	if noGit {
		var paths <-chan sources.ScanTarget
		paths, err = sources.DirectoryTargets(source, detector.Sema, detector.FollowSymlinks)
		if err != nil {
			log.Fatal().Err(err)
		}

		findings, err = detector.DetectFiles(paths)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("failed scan directory")
		}
	} else if fromPipe {
		findings, err = detector.DetectReader(os.Stdin, 10)
		if err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			log.Fatal().Err(err).Msg("failed scan input from stdin")
		}
	} else {
		var (
			gitCmd  *sources.GitCmd
			logOpts string
		)
		logOpts, err = cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err).Msg("could not call GetString() for log-opts")
		}
		gitCmd, err = sources.NewGitLogCmd(source, logOpts)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create Git cmd")
		}
		findings, err = detector.DetectGit(gitCmd)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("failed to scan Git repository")
		}
	}

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}
