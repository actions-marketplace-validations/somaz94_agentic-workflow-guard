package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	os.Clearenv()

	cfg := Load()

	if cfg.InputFile != "" {
		t.Errorf("InputFile = %q, want empty", cfg.InputFile)
	}
	if cfg.OutputFile != "output.txt" {
		t.Errorf("OutputFile = %q, want %q", cfg.OutputFile, "output.txt")
	}
	if cfg.DryRun {
		t.Error("DryRun = true, want false")
	}
}

func TestLoad_FromEnv(t *testing.T) {
	os.Clearenv()
	t.Setenv("INPUT_INPUT_FILE", "data.json")
	t.Setenv("INPUT_OUTPUT_FILE", "result.md")
	t.Setenv("INPUT_DRY_RUN", "true")

	cfg := Load()

	if cfg.InputFile != "data.json" {
		t.Errorf("InputFile = %q, want %q", cfg.InputFile, "data.json")
	}
	if cfg.OutputFile != "result.md" {
		t.Errorf("OutputFile = %q, want %q", cfg.OutputFile, "result.md")
	}
	if !cfg.DryRun {
		t.Error("DryRun = false, want true")
	}
}
