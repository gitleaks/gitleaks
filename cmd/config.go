package cmd

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/config"
)

var (
	// configCmd is inspired by:
	// - Git's `config --list` (https://git-scm.com/docs/git-config#Documentation/git-config.txt-list)
	// - Maven's `help:effective-pom` (https://maven.apache.org/plugins/maven-help-plugin/usage.html)
	configCmd = &cobra.Command{
		Use:   "config",
		Short: "show the config that results from inheritance",
		Run:   runShowConfig,
	}

	source string
)

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.Flags().StringVarP(&source, "source", "s", ".", "path to source")
}

func runShowConfig(cmd *cobra.Command, _ []string) {
	initConfig(source)

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)
	outputConfig := effectiveConfig{
		Title:      cfg.Title,
		Extend:     cfg.Extend,
		Rules:      cfg.GetOrderedRules(),
		Allowlists: cfg.Allowlists,
	}

	// Marshalling cannot be done with Viper.
	// https://github.com/spf13/viper?tab=readme-ov-file#marshalling-to-string
	buf := bytes.Buffer{}
	enc := toml.NewEncoder(&buf).SetIndentTables(true)
	if err := enc.Encode(outputConfig); err != nil {
		log.Fatal().Err(err).Msg("could not encode config")
	}
	out := buf.String()
	re := regexp.MustCompile(`(?m)^(\s*regex\s*=\s*)"(.+)"$`)
	out = re.ReplaceAllStringFunc(out, func(m string) string {
		parts := re.FindStringSubmatch(m)
		// parts[1] == leading "    regex = "
		// parts[2] == the raw inner escaped content
		unq, err := strconv.Unquote(`"` + parts[2] + `"`)
		if err != nil {
			// fallback to the escaped form
			unq = parts[2]
		}
		// wrap in a TOML multi-line literal (no escaping ever)
		// see TOML spec: multi-line literal = '''…''' :contentReference[oaicite:1]{index=1}
		return parts[1] + "'''" + unq + "'''"
	})
	fmt.Println(out)
}

// effectiveConfig matches the structure of `gitleaks.toml`.
// The Config struct is optimized for internal use and does not render easily.
type effectiveConfig struct {
	Title      string              `toml:"title,omitempty"`
	Extend     config.Extend       `toml:"extend,omitempty"`
	Rules      []config.Rule       `toml:"rules,omitempty"`
	Allowlists []*config.Allowlist `toml:"allowlists,omitempty"`
}
