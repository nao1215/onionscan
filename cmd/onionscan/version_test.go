package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	t.Parallel()

	v := getVersion()
	// Should return something (either ldflags value, build info, or "(devel)")
	if v == "" {
		t.Error("getVersion() returned empty string")
	}
}

func TestGetCommit(t *testing.T) {
	t.Parallel()

	c := getCommit()
	// Should return something (either ldflags value, vcs.revision, or "unknown")
	if c == "" {
		t.Error("getCommit() returned empty string")
	}
}

func TestGetDate(t *testing.T) {
	t.Parallel()

	d := getDate()
	// Should return something (either ldflags value, vcs.time, or "unknown")
	if d == "" {
		t.Error("getDate() returned empty string")
	}
}

func TestNewVersionCmd(t *testing.T) {
	t.Parallel()

	cmd := NewVersionCmd()

	t.Run("command has correct use", func(t *testing.T) {
		t.Parallel()
		if cmd.Use != "version" {
			t.Errorf("expected Use to be 'version', got %q", cmd.Use)
		}
	})

	t.Run("command has short description", func(t *testing.T) {
		t.Parallel()
		if cmd.Short == "" {
			t.Error("expected Short to be non-empty")
		}
	})

	t.Run("command outputs version info", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		cmd := NewVersionCmd()
		cmd.SetOut(&buf)
		cmd.SetArgs([]string{})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "onionscan version") {
			t.Errorf("expected output to contain 'onionscan version', got %q", output)
		}
		if !strings.Contains(output, "commit:") {
			t.Errorf("expected output to contain 'commit:', got %q", output)
		}
		if !strings.Contains(output, "built:") {
			t.Errorf("expected output to contain 'built:', got %q", output)
		}
	})
}
