package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "v8.0.0"

func init() {
	// TODO
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display gitleaks version",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println(Version)
}
