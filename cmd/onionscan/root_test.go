package main

import (
	"testing"
)

// TestNewRootCmd tests the root command creation.
func TestNewRootCmd(t *testing.T) {
	t.Parallel()

	cmd := NewRootCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()
		if cmd.Use != "onionscan" {
			t.Errorf("expected use 'onionscan', got %q", cmd.Use)
		}
	})

	t.Run("has short description", func(t *testing.T) {
		t.Parallel()
		if cmd.Short == "" {
			t.Error("expected non-empty short description")
		}
	})

	t.Run("has long description", func(t *testing.T) {
		t.Parallel()
		if cmd.Long == "" {
			t.Error("expected non-empty long description")
		}
	})

	t.Run("has version", func(t *testing.T) {
		t.Parallel()
		if cmd.Version == "" {
			t.Error("expected non-empty version")
		}
	})

	t.Run("has verbose flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.PersistentFlags().Lookup("verbose")
		if flag == nil {
			t.Fatal("expected verbose flag")
		}
		if flag.Shorthand != "v" {
			t.Errorf("expected shorthand 'v', got %q", flag.Shorthand)
		}
		if flag.DefValue != "false" {
			t.Errorf("expected default 'false', got %q", flag.DefValue)
		}
	})

	t.Run("has subcommands", func(t *testing.T) {
		t.Parallel()
		subcommands := cmd.Commands()
		if len(subcommands) == 0 {
			t.Error("expected subcommands")
		}

		// Check for scan and init commands
		hasScans := false
		hasInit := false
		for _, sub := range subcommands {
			if sub.Use == "scan [onion-address]" {
				hasScans = true
			}
			if sub.Use == "init" {
				hasInit = true
			}
		}
		if !hasScans {
			t.Error("expected scan subcommand")
		}
		if !hasInit {
			t.Error("expected init subcommand")
		}
	})

	t.Run("silences usage and errors", func(t *testing.T) {
		t.Parallel()
		if !cmd.SilenceUsage {
			t.Error("expected SilenceUsage to be true")
		}
		if !cmd.SilenceErrors {
			t.Error("expected SilenceErrors to be true")
		}
	})
}
