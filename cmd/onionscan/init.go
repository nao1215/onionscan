package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

//go:embed templates/onionscan.yaml
var configTemplate embed.FS

// configFileName is the default configuration file name.
const configFileName = ".onionscan"

// NewInitCmd creates the init command.
func NewInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new OnionScan configuration file",
		Long: `Initialize creates a new .onionscan configuration file in the current directory.

The generated file includes:
- Default settings for crawl depth and timeouts
- Commented examples for site-specific configurations
- Documentation for all available options

Examples:
  # Create .onionscan in current directory
  onionscan init

  # Create config file at a specific path
  onionscan init -o myconfig.yaml

  # Force overwrite existing file
  onionscan init -f`,
		RunE: runInitCmd,
	}

	cmd.Flags().StringP("output", "o", configFileName,
		"Output file path for the configuration")
	cmd.Flags().BoolP("force", "f", false,
		"Overwrite existing configuration file")

	return cmd
}

// runInitCmd executes the init command.
func runInitCmd(cmd *cobra.Command, _ []string) error {
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return err
	}

	// Check if file already exists
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("configuration file already exists: %s (use -f to overwrite)", outputPath)
		}
	}

	// Read template from embedded filesystem
	content, err := configTemplate.ReadFile("templates/onionscan.yaml")
	if err != nil {
		return fmt.Errorf("failed to read config template: %w", err)
	}

	// Create parent directories if needed
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Write configuration file
	if err := os.WriteFile(outputPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	fmt.Printf("Created configuration file: %s\n", outputPath)
	fmt.Println("\nEdit this file to configure site-specific settings such as:")
	fmt.Println("  - Authentication cookies and headers")
	fmt.Println("  - Crawl depth per site")
	fmt.Println("  - URL patterns to ignore or follow")

	return nil
}
