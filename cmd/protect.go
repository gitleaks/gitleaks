package cmd

import (
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "protect secrets in code",
	Run:   runProtect,
}

func runProtect(cmd *cobra.Command, args []string) {
	initConfig()
	var err error

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	exitCode, _ := cmd.Flags().GetInt("exit-code")
	staged, _ := cmd.Flags().GetBool("staged")
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	start := time.Now()
	detector := Detector(cmd, cfg, source)

	// start git scan
	var findings []report.Finding
	gitCmd, err := sources.NewGitDiffCmd(source, staged)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	findings, err = detector.DetectGit(gitCmd)

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}
