package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	apiBaseURL = "http://localhost:8080"
)

var rootCmd = &cobra.Command{
	Use:     "cvscan [flags] [repos-path]",
	Short:   "Cloudvisor Security Scanner — secrets & IaC scanning",
	Version: version,
	Args:    cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		token, _ := cmd.Flags().GetString("token")
		output, _ := cmd.Flags().GetString("output")
		scanners, _ := cmd.Flags().GetString("scanners")

		reposPath := ""
		if len(args) > 0 {
			reposPath = args[0]
		}

		// If no repos path, launch TUI
		if reposPath == "" {
			return runTUI(cmd.Context())
		}

		return runCLI(cmd.Context(), CLIConfig{
			ID:        id,
			Token:     token,
			ReposPath: reposPath,
			Output:    output,
			Scanners:  scanners,
		})
	},
}

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit previous scan results to Cloudvisor",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		token, _ := cmd.Flags().GetString("token")
		file, _ := cmd.Flags().GetString("file")

		if id == "" {
			return fmt.Errorf("--id is required for submission")
		}
		if token == "" {
			return fmt.Errorf("--token is required for submission")
		}

		return runSubmit(cmd.Context(), id, token, file)
	},
}

func init() {
	rootCmd.Flags().String("id", "", "engagement ID (eng_xxx)")
	rootCmd.Flags().String("token", "", "standalone token (tok_xxx) — required with --id")
	rootCmd.Flags().StringP("output", "o", "cvscan-report.html", "HTML report output path")
	rootCmd.Flags().String("scanners", "secrets,iac", "comma-separated scanners to run (secrets, iac)")

	submitCmd.Flags().String("id", "", "engagement ID (eng_xxx)")
	submitCmd.Flags().String("token", "", "standalone token (tok_xxx)")
	submitCmd.Flags().String("file", ".cvscan-results.json", "path to results JSON file")
	rootCmd.AddCommand(submitCmd)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
