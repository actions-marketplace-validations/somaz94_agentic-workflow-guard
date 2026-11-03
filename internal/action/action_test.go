package action

import (
	"strings"
	"testing"

	"github.com/YOUR_USERNAME/YOUR_ACTION/internal/config"
)

func TestRun_Default(t *testing.T) {
	cfg := &config.Config{
		OutputFile: "output.txt",
	}

	result, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Content == "" {
		t.Error("Run() returned empty content")
	}
}

func TestRun_WithInputFile(t *testing.T) {
	cfg := &config.Config{
		InputFile:  "test.json",
		OutputFile: "output.txt",
	}

	result, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(result.Content, "test.json") {
		t.Errorf("Run() content = %q, want to contain input file name", result.Content)
	}
}
