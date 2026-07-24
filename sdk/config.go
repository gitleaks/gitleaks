package sdk

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
)

var viperMu sync.Mutex

// LoadConfigFromFile reads and translates a gitleaks TOML config file.
func LoadConfigFromFile(path string) (config.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return config.Config{}, err
	}
	defer file.Close()

	return loadConfig(path, file)
}

// LoadConfigFromString reads and translates an in-memory gitleaks TOML config.
func LoadConfigFromString(toml string) (config.Config, error) {
	return loadConfig("", strings.NewReader(toml))
}

// LoadDefaultConfig reads and translates the embedded default gitleaks config.
func LoadDefaultConfig() (config.Config, error) {
	return loadConfig("", strings.NewReader(config.DefaultConfig))
}

func loadConfig(path string, reader io.Reader) (config.Config, error) {
	viperMu.Lock()
	defer viperMu.Unlock()

	viper.Reset()
	defer viper.Reset()

	if path != "" {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			return config.Config{}, err
		}
	} else {
		viper.SetConfigType("toml")
		if err := viper.ReadConfig(reader); err != nil {
			return config.Config{}, err
		}
	}

	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	return vc.Translate()
}
