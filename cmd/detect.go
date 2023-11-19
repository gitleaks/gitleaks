package cmd

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringSlice("enable-rule", []string{}, "only enable specific rules by id, ex: `gitleaks detect --enable-rule=atlassian-api-token --enable-rule=slack-access-token`")
	detectCmd.Flags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore file or folder containing one")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "detect secrets in code",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	initConfig()
	var (
		findings []report.Finding
		err      error
	)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	// grab source
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
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
		log.Fatal().Err(err)
	}

	// start the detector scan
	if noGit {
		findings, err = detector.DetectFiles(source)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	} else if fromPipe {
		findings, err = detector.DetectReader(os.Stdin, 10)
		if err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			log.Fatal().Err(err).Msg("")
		}
	} else {
		var logOpts string
		logOpts, err = cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
		findings, err = detector.DetectGit(source, logOpts, detect.DetectType)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	}

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}

