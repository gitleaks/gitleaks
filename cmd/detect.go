package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/detect/git"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | gitleaks detect --pipe`")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringSlice("enable-rule", []string{}, "only enable specific rules by id, ex: `gitleaks detect --enable-rule=atlassian-api-token --enable-rule=slack-access-token`")
	detectCmd.Flags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore file or folder containing one")
	detectCmd.Flags().String("gitleaks-ignore-rev", "HEAD", "git revision where .gitleaksignore can be found (useful in bare repositories without working tree)")
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
	gitleaksIgnoreRev, err := cmd.Flags().GetString("gitleaks-ignore-rev")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get revision")
	}

	if fileExists(gitleaksIgnorePath) {
		if err = detector.AddGitleaksIgnore(gitleaksIgnorePath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	} else if gitPath := gitleaksIgnoreRev + ":" + gitleaksIgnorePath; fileExistsInGit(gitPath) {
		if err = detector.AddGitleaksIgnoreFromGit(gitPath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnoreFromGit")
		}
	}

	if path := filepath.Join(gitleaksIgnorePath, ".gitleaksignore"); fileExists(path) {
		if err = detector.AddGitleaksIgnore(path); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	} else if gitPath := gitleaksIgnoreRev + ":" + path; fileExistsInGit(gitPath) {
		if err = detector.AddGitleaksIgnoreFromGit(gitPath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnoreFromGit")
		}
	}

	if path := filepath.Join(source, ".gitleaksignore"); fileExists(path) {
		if err = detector.AddGitleaksIgnore(path); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	} else if gitPath := gitleaksIgnoreRev + ":" + path; fileExistsInGit(gitPath) {
		if err = detector.AddGitleaksIgnoreFromGit(gitPath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnoreFromGit")
		}
	}

	// ignore findings from the baseline (an existing report in json format generated earlier)
	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath != "" {
		err = detector.AddBaseline(baselinePath, source)
		if err != nil {
			log.Error().Msgf("Could not load baseline. The path must point of a gitleaks report generated using the default format: %s", err)
		}
	}

	// If set, only apply rules that are defined in the flag
	rules, _ := cmd.Flags().GetStringSlice("enable-rule")
	if len(rules) > 0 {
		log.Info().Msg("Overriding enabled rules: " + strings.Join(rules, ", "))
		ruleOverride := make(map[string]config.Rule)
		for _, ruleName := range rules {
			if rule, ok := cfg.Rules[ruleName]; ok {
				ruleOverride[ruleName] = rule
			} else {
				log.Fatal().Msgf("Requested rule %s not found in rules", ruleName)
			}
		}
		detector.Config.Rules = ruleOverride
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

func fileExistsInGit(filename string) bool {
	exists, err := git.FileExists(filename)
	if err != nil {
		return false
	}

	return exists
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}
