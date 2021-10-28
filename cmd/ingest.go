package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
)

func init() {
	// TODO
	rootCmd.AddCommand(ingestCmd)
}

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Detect secrets from pipe",
	Run:   runIngest,
}

func runIngest(cmd *cobra.Command, args []string) {
	var cfg config.Config

	viper.Unmarshal(&cfg)
	cfg.Compile()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		fmt.Println(input)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal().Err(err).Msg("Failed ingest from stdin")
	}
}
