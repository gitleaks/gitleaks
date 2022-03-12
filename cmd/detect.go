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
		findings []report.Finding
		err      error
	)

	// Load config
	if err = viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg.Path, _ = cmd.Flags().GetString("config")

	// start timer
	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err)
	}
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err)
	}
	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	if detector.Config.Path == "" {
		detector.Config.Path = filepath.Join(source, ".gitleaks.toml")
	}
	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err)
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetBool("redact"); err != nil {
		log.Fatal().Err(err)
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err)
	}

	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	noGit, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		log.Fatal().Err(err)
	}

	// start the detector scan
	if noGit {
		findings, err = detector.DetectFiles(source)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err)
		}

	} else {
		logOpts, err := cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err)
		}
		findings, err = detector.DetectGit(source, logOpts, detect.DetectType)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err)
		}
	}

	// log info about the scan
	log.Info().Msgf("scan completed in %s", time.Since(start))
	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}

	// write report if desired
	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err = report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err)
		}
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}
