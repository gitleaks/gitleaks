package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "version is set by build process"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "display gitleaks version",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println(Version)
}
