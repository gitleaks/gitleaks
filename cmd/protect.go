package cmd

import (
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
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

	// get log options for git scan
	logOpts, err := cmd.Flags().GetString("log-opts")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// start git scan
	var findings []report.Finding
	if staged {
		findings, err = detector.DetectGit(source, logOpts, detect.ProtectStagedType)
	} else {
		findings, err = detector.DetectGit(source, logOpts, detect.ProtectType)
	}

	findingSummaryAndExit(findings, cmd, cfg, exitCode, start, err)
}
