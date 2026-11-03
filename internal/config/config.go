// Package config loads the action inputs from INPUT_* environment variables.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds the action configuration.
type Config struct {
	Path        string
	FailOn      string
	SARIFFile   string
	IgnoreRules []string
}

// Load reads and validates the inputs.
func Load() (*Config, error) {
	c := &Config{
		Path:      getEnv("INPUT_PATH", "."),
		FailOn:    strings.ToLower(getEnv("INPUT_FAIL_ON", "high")),
		SARIFFile: os.Getenv("INPUT_SARIF_FILE"),
	}
	switch c.FailOn {
	case "high", "medium", "low", "none":
	default:
		return nil, fmt.Errorf("fail_on must be high, medium, low or none, got %q", c.FailOn)
	}
	for _, r := range strings.Split(os.Getenv("INPUT_IGNORE_RULES"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.IgnoreRules = append(c.IgnoreRules, r)
		}
	}
	return c, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
