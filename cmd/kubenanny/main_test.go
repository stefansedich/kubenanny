package main

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := parseLogLevel(tt.input); got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"version"})

	var buf bytes.Buffer
	root.SetOut(&buf)

	if err := root.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if got := buf.String(); got != "dev\n" {
		t.Errorf("version output = %q, want %q", got, "dev\n")
	}
}

func TestRootCmdFlags(t *testing.T) {
	root := newRootCmd()

	tests := []struct {
		flag     string
		defValue string
	}{
		{"health-addr", "127.0.0.1:9090"},
		{"probe-addr", ":8081"},
		{"log-level", "info"},
	}
	for _, tt := range tests {
		f := root.Flags().Lookup(tt.flag)
		if f == nil {
			t.Errorf("flag %q not found", tt.flag)
			continue
		}
		if f.DefValue != tt.defValue {
			t.Errorf("flag %q default = %q, want %q", tt.flag, f.DefValue, tt.defValue)
		}
	}
}

func TestRootCmdHelp(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"--help"})

	var buf bytes.Buffer
	root.SetOut(&buf)

	if err := root.Execute(); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("help output should not be empty")
	}
}
