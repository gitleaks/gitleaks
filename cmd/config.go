package cmd

import (
	"bytes"
	"fmt"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/config"
)

// configCmd is inspired by:
// - Git's `config --list` (https://git-scm.com/docs/git-config#Documentation/git-config.txt-list)
// - Maven's `help:effective-pom` (https://maven.apache.org/plugins/maven-help-plugin/usage.html)
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "show the config that results from inheritance",
	Run:   runShowConfig,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.Flags().StringP("source", "s", ".", "path to source")
}

func runShowConfig(cmd *cobra.Command, args []string) {
	source := mustGetStringFlag(cmd, "source")
	initConfig(source)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)
	outputConfig := effectiveConfig{
		Title:     cfg.Title,
		Extend:    cfg.Extend,
		Rules:     cfg.GetOrderedRules(),
		Allowlist: cfg.Allowlist,
	}

	// Marshalling cannot be done with Viper.
	// https://github.com/spf13/viper?tab=readme-ov-file#marshalling-to-string
	buf := bytes.Buffer{}
	enc := toml.NewEncoder(&buf).SetIndentTables(true)
	if err := enc.Encode(outputConfig); err != nil {
		log.Fatal().Err(err).Msg("could not encode config")
	}
	fmt.Println(buf.String())
}

// effectiveConfig matches the structure of `gitleaks.toml`.
// The Config struct is optimized for internal use and does not render easily.
type effectiveConfig struct {
	Title     string            `toml:"title,omitempty"`
	Extend    config.Extend     `toml:"extend,omitempty"`
	Rules     []config.Rule     `toml:"rules,omitempty"`
	Allowlist *config.Allowlist `toml:"allowlist,omitempty"`
}
