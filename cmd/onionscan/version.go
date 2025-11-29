package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Version information set at build time via ldflags.
var (
	version = ""
	commit  = ""
	date    = ""
)

// getVersion returns version string.
// Priority: ldflags > debug.ReadBuildInfo > "(devel)"
func getVersion() string {
	if version != "" {
		return version
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		if buildInfo.Main.Version != "" {
			return buildInfo.Main.Version
		}
	}
	return "(devel)"
}

// getCommit returns commit hash.
// Priority: ldflags > debug.ReadBuildInfo > "unknown"
func getCommit() string {
	if commit != "" {
		return commit
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				if len(setting.Value) > 7 {
					return setting.Value[:7]
				}
				return setting.Value
			}
		}
	}
	return "unknown"
}

// getDate returns build date.
// Priority: ldflags > debug.ReadBuildInfo > "unknown"
func getDate() string {
	if date != "" {
		return date
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.time" {
				return setting.Value
			}
		}
	}
	return "unknown"
}

// NewVersionCmd creates the version command.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print the version, commit hash, and build date of onionscan.`,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "onionscan version %s\n", getVersion())
			fmt.Fprintf(cmd.OutOrStdout(), "  commit: %s\n", getCommit())
			fmt.Fprintf(cmd.OutOrStdout(), "  built:  %s\n", getDate())
		},
	}
}
