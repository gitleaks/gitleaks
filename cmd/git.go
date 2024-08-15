package cmd

import (
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
    gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "detect secrets in git repositories",
    Args:  cobra.MaximumNArgs(1), // Allows for at most one positional argument (the repo path)
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
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
		log.Fatal().Err(err).Msg("could not get source")
	}
	detector := Detector(cmd, cfg, source)

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

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

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}
