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
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")

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
		log.Fatal().Err(err).Msg("")
	}
	source, err := cmd.Flags().GetString("source")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	if detector.Config.Path == "" {
		detector.Config.Path = filepath.Join(source, ".gitleaks.toml")
	}
	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetBool("redact"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	if detector.MaxTargetMegaBytes, err = cmd.Flags().GetInt("max-target-megabytes"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	if fileExists(filepath.Join(source, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(source, ".gitleaksignore")); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	// ignore findings from the baseline (an existing report in json format generated earlier)
	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath != "" {
		err = detector.AddBaseline(baselinePath)
		if err != nil {
			log.Error().Msgf("Could not load baseline. The path must point of a gitleaks report generated using the default format: %s", err)
		}
	}

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get exit code")
	}

	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	noGit, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		log.Fatal().Err(err).Msg("could not call GetBool() for no-git")
	}
	fromPipe, err := cmd.Flags().GetBool("pipe")
	if err != nil {
		log.Fatal().Err(err)
	}

	// start the detector scan
	if noGit {
		findings, err = detector.DetectFiles(source)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	} else if fromPipe {
		findings, err = detector.DetectReader(os.Stdin, 10)
		if err != nil {
			// log fatal to exit, no need to continue since a report
			// will not be generated when scanning from a pipe...for now
			log.Fatal().Err(err).Msg("")
		}
	} else {
		var logOpts string
		logOpts, err = cmd.Flags().GetString("log-opts")
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
		findings, err = detector.DetectGit(source, logOpts, detect.DetectType)
		if err != nil {
			// don't exit on error, just log it
			log.Error().Err(err).Msg("")
		}
	}

	// log info about the scan
	if err == nil {
		log.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			log.Warn().Msgf("leaks found: %d", len(findings))
		} else {
			log.Info().Msg("no leaks found")
		}
	} else {
		log.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			log.Warn().Msgf("%d leaks found in partial scan", len(findings))
		} else {
			log.Warn().Msg("no leaks found in partial scan")
		}
	}

	// write report if desired
	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err := report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("could not write")
		}
	}

	if err != nil {
		os.Exit(1)
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}

func fileExists(fileName string) bool {
	// check for a .gitleaksignore file
	info, err := os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return false
	}

	if info != nil && err == nil {
		if !info.IsDir() {
			return true
		}
	}
	return false
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}
