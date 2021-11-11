package cmd

import (
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
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Protect secrets in code",
	Run:   runProtect,
}

func runProtect(cmd *cobra.Command, args []string) {
	var vc config.ViperConfig

	viper.Unmarshal(&vc)
	cfg := vc.Translate()

	source, _ := cmd.Flags().GetString("source")
	verbosity, _ := cmd.Flags().GetBool("verbose")
	redact, _ := cmd.Flags().GetBool("redact")
	start := time.Now()

	files, err := git.GitDiff(source)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get git log")
	}

	findings := detect.FromGit(files, cfg, detect.Options{Verbose: verbosity, Redact: redact})
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
}
