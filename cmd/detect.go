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
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "detect secrets in code",
	Run:   runDetect,
}

func runDetect(cmd *cobra.Command, args []string) {
	initConfig()
	var (
		vc       config.ViperConfig
		findings []*report.Finding
		err      error
	)

	viper.Unmarshal(&vc)
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	source, _ := cmd.Flags().GetString("source")
	logOpts, _ := cmd.Flags().GetString("log-opts")
	verbose, _ := cmd.Flags().GetBool("verbose")
	redact, _ := cmd.Flags().GetBool("redact")
	noGit, _ := cmd.Flags().GetBool("no-git")
	start := time.Now()

	if noGit {
		if logOpts != "" {
			log.Fatal().Err(err).Msg("--log-opts cannot be used with --no-git")
		}
		findings, err = detect.FromFiles(source, cfg, detect.Options{
			Verbose: verbose,
			Redact:  redact,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to scan files")
		}
	} else {
		files, err := git.GitLog(source, logOpts)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get git log")
		}

		findings = detect.FromGit(files, cfg, detect.Options{Verbose: verbose, Redact: redact})
	}

	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}

	log.Info().Msgf("scan completed in %s", time.Since(start))

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		report.Write(findings, cfg, ext, reportPath)
	}
}
