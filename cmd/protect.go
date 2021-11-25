package cmd

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/git"
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
	var vc config.ViperConfig

	viper.Unmarshal(&vc)
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.Path, _ = cmd.Flags().GetString("config")
	source, _ := cmd.Flags().GetString("source")
	verbose, _ := cmd.Flags().GetBool("verbose")
	redact, _ := cmd.Flags().GetBool("redact")
	exitCode, _ := cmd.Flags().GetInt("exit-code")
	staged, _ := cmd.Flags().GetBool("staged")
	if cfg.Path == "" {
		cfg.Path = filepath.Join(source, ".gitleaks.toml")
	}
	start := time.Now()

	files, err := git.GitDiff(source, staged)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get git log")
	}

	findings := detect.FromGit(files, cfg, detect.Options{Verbose: verbose, Redact: redact})
	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}

	log.Info().Msgf("scan duration: %s", time.Since(start))

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		report.Write(findings, cfg, ext, reportPath)
	}
	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}
