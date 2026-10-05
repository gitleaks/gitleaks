package cmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringP("config", "c", "", "")
	cmd.Flags().Int("exit-code", 1, "")
	cmd.Flags().StringP("report-path", "r", "", "")
	cmd.Flags().StringP("report-format", "f", "", "")
	cmd.Flags().StringP("report-template", "", "", "")
	cmd.Flags().StringP("baseline-path", "b", "", "")
	cmd.Flags().StringP("log-level", "l", "info", "")
	cmd.Flags().BoolP("verbose", "v", false, "")
	cmd.Flags().BoolP("no-color", "", false, "")
	cmd.Flags().Int("max-target-megabytes", 0, "")
	cmd.Flags().BoolP("ignore-gitleaks-allow", "", false, "")
	cmd.Flags().Uint("redact", 0, "")
	cmd.Flag("redact").NoOptDefVal = "100"
	cmd.Flags().Bool("no-banner", false, "")
	cmd.Flags().StringSlice("enable-rule", []string{}, "")
	cmd.Flags().StringP("gitleaks-ignore-path", "i", ".", "")
	cmd.Flags().Int("max-decode-depth", 5, "")
	cmd.Flags().Int("max-archive-depth", 0, "")
	cmd.Flags().Int("timeout", 0, "")
	return cmd
}

func uintPtr(u uint) *uint {
	return &u
}

func TestDetectorReportConfigPrecedence(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("config redact applied when CLI flag not changed", func(t *testing.T) {
		cmd := newTestCmd()
		cfg := config.Config{
			Report: config.Report{
				Redact: uintPtr(80),
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, uint(80), detector.Redact)
	})

	t.Run("CLI redact flag takes precedence over config redact", func(t *testing.T) {
		cmd := newTestCmd()
		err := cmd.Flags().Set("redact", "25")
		require.NoError(t, err)

		cfg := config.Config{
			Report: config.Report{
				Redact: uintPtr(100),
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, uint(25), detector.Redact)
	})

	t.Run("CLI redact=0 takes precedence over config redact=100", func(t *testing.T) {
		cmd := newTestCmd()
		err := cmd.Flags().Set("redact", "0")
		require.NoError(t, err)

		cfg := config.Config{
			Report: config.Report{
				Redact: uintPtr(100),
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, uint(0), detector.Redact)
	})

	t.Run("config report path applied when CLI flag not changed", func(t *testing.T) {
		cmd := newTestCmd()
		targetReport := filepath.Join(tempDir, "config-report.json")
		cfg := config.Config{
			Report: config.Report{
				Path: targetReport,
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, targetReport, detector.ReportPath)
		assert.IsType(t, &report.JsonReporter{}, detector.Reporter)
	})

	t.Run("CLI report-path flag takes precedence over config report path", func(t *testing.T) {
		cmd := newTestCmd()
		cliReport := filepath.Join(tempDir, "cli-report.json")
		err := cmd.Flags().Set("report-path", cliReport)
		require.NoError(t, err)

		configReport := filepath.Join(tempDir, "config-report.json")
		cfg := config.Config{
			Report: config.Report{
				Path: configReport,
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, cliReport, detector.ReportPath)
	})

	t.Run("config report format applied when CLI flag not changed", func(t *testing.T) {
		cmd := newTestCmd()
		targetReport := filepath.Join(tempDir, "config-report.out")
		cfg := config.Config{
			Report: config.Report{
				Path:   targetReport,
				Format: "csv",
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, targetReport, detector.ReportPath)
		assert.IsType(t, &report.CsvReporter{}, detector.Reporter)
	})

	t.Run("CLI report-format flag takes precedence over config report format", func(t *testing.T) {
		cmd := newTestCmd()
		targetReport := filepath.Join(tempDir, "report.out")
		err := cmd.Flags().Set("report-format", "sarif")
		require.NoError(t, err)

		cfg := config.Config{
			Report: config.Report{
				Path:   targetReport,
				Format: "csv",
			},
		}

		detector := Detector(cmd, cfg, tempDir)
		assert.Equal(t, targetReport, detector.ReportPath)
		assert.IsType(t, &report.SarifReporter{}, detector.Reporter)
	})
}
