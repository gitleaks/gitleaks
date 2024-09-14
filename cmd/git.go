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
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	var (
		findings []report.Finding
		err      error
	)

	// grab source
    source := "."
    if len(args) == 1 {
	    source = args[0]
	if source == "" {
		source = "."
	}
    }

	initConfig(source)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	// grab source
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
