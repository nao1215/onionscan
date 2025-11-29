// Package main provides the entry point for the OnionScan CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCmd creates the root command for OnionScan.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onionscan",
		Short: "Security auditing tool for Tor hidden services",
		Long: `OnionScan is a security auditing tool for Tor hidden services (.onion addresses).
It identifies OPSEC issues, configuration errors, and anonymity risks.

By default, OnionScan starts an embedded Tor daemon automatically.
Use --external-tor to use an existing Tor proxy instead.`,
		Version:       getVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags that apply to all commands
	cmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")

	// Add subcommands
	cmd.AddCommand(NewScanCmd())
	cmd.AddCommand(NewCompareCmd())
	cmd.AddCommand(NewInitCmd())
	cmd.AddCommand(NewVersionCmd())

	return cmd
}

// Execute runs the root command.
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
