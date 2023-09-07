package cmd

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	protectCmd.Flags().String("log-opts", "", "git log options")
	protectCmd.Flags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore file or folder containing one")
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

	if err := viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.Path, _ = cmd.Flags().GetString("config")
	exitCode, _ := cmd.Flags().GetInt("exit-code")
	staged, _ := cmd.Flags().GetBool("staged")
	start := time.Now()

	// Setup detector
	detector := detect.NewDetector(cfg)
	// set color flag at first
	if detector.NoColor, err = cmd.Flags().GetBool("no-color"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// also init logger again without color
	if detector.NoColor {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: detector.NoColor,
		})
	}
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	sourceList, err := cmd.Flags().GetStringSlice("source")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	multipleSources := len(sourceList) > 1
	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	// This only takes effect if a single source is set
	if !multipleSources {
		source := sourceList[0]
		if detector.Config.Path == "" {
			detector.Config.Path = filepath.Join(source, ".gitleaks.toml")
		}
	}

	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetUint("redact"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	if detector.MaxTargetMegaBytes, err = cmd.Flags().GetInt("max-target-megabytes"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// set ignore gitleaks:allow flag
	if detector.IgnoreGitleaksAllow, err = cmd.Flags().GetBool("ignore-gitleaks-allow"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	gitleaksIgnorePath, err := cmd.Flags().GetString("gitleaks-ignore-path")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get .gitleaksignore path")
	}

	if fileExists(gitleaksIgnorePath) {
		if err = detector.AddGitleaksIgnore(gitleaksIgnorePath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if fileExists(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if !multipleSources {
		source := sourceList[0]
		if fileExists(filepath.Join(source, ".gitleaksignore")) {
			if err = detector.AddGitleaksIgnore(filepath.Join(source, ".gitleaksignore")); err != nil {
				log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
			}
		}
	}

	// get log options for git scan
	logOpts, err := cmd.Flags().GetString("log-opts")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// start git scan
	var findings []report.Finding
	for _, source := range sourceList {
		if staged {
			findings, err = detector.DetectGit(source, logOpts, detect.ProtectStagedType)
		} else {
			findings, err = detector.DetectGit(source, logOpts, detect.ProtectType)
		}
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	}

	// log info about the scan
	log.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
	if len(findings) != 0 {
		log.Warn().Msgf("leaks found: %d", len(findings))
	} else {
		log.Info().Msg("no leaks found")
	}

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err = report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("")
		}
	}
	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}
