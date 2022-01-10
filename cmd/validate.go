package cmd

import (
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate example secrets in config",
	Run:   runValidate,
}

func init() {
	validateCmd.Flags().String("rule-id", "", "rule id")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) {
	initConfig()
	var (
		vc       config.ViperConfig
		findings []report.Finding
		err      error
	)

	viper.Unmarshal(&vc)
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg.Path, _ = cmd.Flags().GetString("config")
	ruleID, _ := cmd.Flags().GetString("rule-id")

	if cfg.Path == "" {
		log.Fatal().Msg("config file not specified")
	}

	start := time.Now()

	for _, v := range cfg.Rules {
		if ruleID == "" || ruleID == v.RuleID {
			findings = append(findings, detect.ValidateExamples(cfg, v.RuleID)...)
		}
	}

	log.Info().Msgf("config validation completed in %s", time.Since(start))

	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		report.Write(findings, cfg, ext, reportPath)
	}

}
