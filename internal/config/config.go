package config

import (
	"os"
	"strings"
)

// Config holds the action configuration loaded from environment variables.
type Config struct {
	InputFile  string
	OutputFile string
	DryRun     bool
}

// Load reads configuration from INPUT_* environment variables.
func Load() *Config {
	return &Config{
		InputFile:  getEnv("INPUT_INPUT_FILE", ""),
		OutputFile: getEnv("INPUT_OUTPUT_FILE", "output.txt"),
		DryRun:     strings.EqualFold(getEnv("INPUT_DRY_RUN", "false"), "true"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
