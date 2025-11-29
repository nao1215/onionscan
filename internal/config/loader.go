package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFile is the default configuration file name.
const DefaultConfigFile = ".onionscan"

// ErrConfigNotFound is returned when the configuration file does not exist.
var ErrConfigNotFound = errors.New("configuration file not found")

// LoadConfigFile loads site configurations from a YAML file.
// If the file does not exist, it returns ErrConfigNotFound.
// Callers should handle this error appropriately based on whether
// the config file path was explicitly specified by the user.
func LoadConfigFile(path string) (*File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // User-provided config path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, err
	}

	var cf File
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}

	// Initialize Sites map if nil
	if cf.Sites == nil {
		cf.Sites = make(map[string]SiteConfig)
	}

	return &cf, nil
}

// FindConfigFile searches for the configuration file in the following order:
// 1. If configPath is specified, use it directly
// 2. Look for .onionscan in the current directory
// 3. Look for .onionscan in the user's home directory
//
// Returns the path to the configuration file if found, or empty string if not found.
func FindConfigFile(configPath string) string {
	// If explicit path is provided, use it
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
		return ""
	}

	// Check current directory
	cwd, err := os.Getwd()
	if err == nil {
		cwdConfig := filepath.Join(cwd, DefaultConfigFile)
		if _, err := os.Stat(cwdConfig); err == nil {
			return cwdConfig
		}
	}

	// Check home directory
	home, err := os.UserHomeDir()
	if err == nil {
		homeConfig := filepath.Join(home, DefaultConfigFile)
		if _, err := os.Stat(homeConfig); err == nil {
			return homeConfig
		}
	}

	return ""
}
