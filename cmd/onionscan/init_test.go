package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNewInitCmd tests the init command creation.
func TestNewInitCmd(t *testing.T) {
	t.Parallel()

	cmd := NewInitCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()
		if cmd.Use != "init" {
			t.Errorf("expected use 'init', got %q", cmd.Use)
		}
	})

	t.Run("has short description", func(t *testing.T) {
		t.Parallel()
		if cmd.Short == "" {
			t.Error("expected non-empty short description")
		}
	})

	t.Run("has output flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("output")
		if flag == nil {
			t.Fatal("expected output flag")
		}
		if flag.Shorthand != "o" {
			t.Errorf("expected shorthand 'o', got %q", flag.Shorthand)
		}
		if flag.DefValue != configFileName {
			t.Errorf("expected default %q, got %q", configFileName, flag.DefValue)
		}
	})

	t.Run("has force flag", func(t *testing.T) {
		t.Parallel()
		flag := cmd.Flags().Lookup("force")
		if flag == nil {
			t.Fatal("expected force flag")
		}
		if flag.Shorthand != "f" {
			t.Errorf("expected shorthand 'f', got %q", flag.Shorthand)
		}
		if flag.DefValue != "false" {
			t.Errorf("expected default 'false', got %q", flag.DefValue)
		}
	})
}

// TestRunInitCmd tests the init command execution.
func TestRunInitCmd(t *testing.T) {
	t.Run("creates config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".onionscan")

		cmd := NewInitCmd()
		cmd.SetArgs([]string{"-o", outputPath})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected config file to be created")
		}

		// Verify file contents
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		// Check for expected YAML keys
		if !strings.Contains(string(content), "defaults:") {
			t.Error("expected config to contain 'defaults:'")
		}
		if !strings.Contains(string(content), "sites:") {
			t.Error("expected config to contain 'sites:'")
		}
	})

	t.Run("fails if file exists without force", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".onionscan")

		// Create existing file
		if err := os.WriteFile(outputPath, []byte("existing"), 0600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		cmd := NewInitCmd()
		cmd.SetArgs([]string{"-o", outputPath})

		err := cmd.Execute()
		if err == nil {
			t.Error("expected error when file exists")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
		}
	})

	t.Run("overwrites file with force flag", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".onionscan")

		// Create existing file
		if err := os.WriteFile(outputPath, []byte("existing"), 0600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		cmd := NewInitCmd()
		cmd.SetArgs([]string{"-o", outputPath, "-f"})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify file was overwritten
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) == "existing" {
			t.Error("expected file to be overwritten")
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "subdir", "nested", ".onionscan")

		cmd := NewInitCmd()
		cmd.SetArgs([]string{"-o", outputPath})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("expected config file to be created in nested directory")
		}
	})

	t.Run("file has correct permissions", func(t *testing.T) {
		// Skip on Windows as it doesn't support Unix-style file permissions
		if runtime.GOOS == "windows" {
			t.Skip("skipping permission test on Windows")
		}

		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, ".onionscan")

		cmd := NewInitCmd()
		cmd.SetArgs([]string{"-o", outputPath})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		info, err := os.Stat(outputPath)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}

		// Check file permissions (0600)
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("expected permissions 0600, got %o", perm)
		}
	})
}

// TestConfigTemplate tests the embedded config template.
func TestConfigTemplate(t *testing.T) {
	t.Parallel()

	content, err := configTemplate.ReadFile("templates/onionscan.yaml")
	if err != nil {
		t.Fatalf("failed to read template: %v", err)
	}

	t.Run("template is not empty", func(t *testing.T) {
		t.Parallel()
		if len(content) == 0 {
			t.Error("expected non-empty template")
		}
	})

	t.Run("template is valid YAML", func(t *testing.T) {
		t.Parallel()
		// Basic YAML structure check
		str := string(content)
		if !strings.Contains(str, ":") {
			t.Error("expected template to contain YAML key-value pairs")
		}
	})

	t.Run("template contains defaults section", func(t *testing.T) {
		t.Parallel()
		if !strings.Contains(string(content), "defaults:") {
			t.Error("expected template to contain 'defaults:' section")
		}
	})

	t.Run("template contains sites section", func(t *testing.T) {
		t.Parallel()
		if !strings.Contains(string(content), "sites:") {
			t.Error("expected template to contain 'sites:' section")
		}
	})

	t.Run("template contains documentation comments", func(t *testing.T) {
		t.Parallel()
		if !strings.Contains(string(content), "#") {
			t.Error("expected template to contain documentation comments")
		}
	})
}
