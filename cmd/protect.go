package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	protectCmd.Flags().String("log-opts", "", "git log options")
	protectCmd.Flags().StringP("source", "s", ".", "path to source")
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:    "protect",
	Short:  "protect secrets in code",
	Run:    runProtect,
	Hidden: true,
}

func runProtect(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()
	source := mustGetStringFlag(cmd, "source")

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	staged := mustGetBoolFlag(cmd, "staged")

	// start git scan
	var (
		findings []report.Finding
		err      error

		gitCmd *sources.GitCmd
		remote *detect.RemoteInfo
	)

	if gitCmd, err = sources.NewGitDiffCmd(source, staged); err != nil {
		logging.Fatal().Err(err).Msg("could not create Git diff cmd")
	}
	remote = &detect.RemoteInfo{Platform: scm.NoPlatform}

	if findings, err = detector.DetectGit(gitCmd, remote); err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}
	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
