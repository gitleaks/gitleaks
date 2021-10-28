package cmd

import (
	"fmt"
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
	var cfg config.Config

	viper.Unmarshal(&cfg)
	cfg.Compile()

	source, _ := cmd.Flags().GetString("source")
	verbosity, _ := cmd.Flags().GetBool("verbose")
	redact, _ := cmd.Flags().GetBool("redact")
	start := time.Now()

	files, err := git.GitDiff(source)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get git log")
	}

	findings := detect.FromGit(files, cfg, detect.Options{Verbose: verbosity, Redact: redact})

	// log duration of scan using durafmt
	log.Info().Msgf("scan completed in %s", time.Since(start))

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		fmt.Println("writing path")
		report.Write(findings, ext, reportPath)
	}
}
