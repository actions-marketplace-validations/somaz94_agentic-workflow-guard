// Package action runs one scan from a loaded configuration.
package action

import (
	"fmt"
	"os"

	"github.com/somaz94/agentic-workflow-guard/internal/audit"
	"github.com/somaz94/agentic-workflow-guard/internal/config"
	"github.com/somaz94/agentic-workflow-guard/internal/registry"
	"github.com/somaz94/agentic-workflow-guard/internal/report"
)

// Version is stamped into the SARIF driver.
var Version = "dev"

// repoName is the repository being scanned, when the path is the checkout this run
// belongs to. A `path:` elsewhere could hold anything, so its name stays unknown.
func repoName(path string) string {
	if path == "." || path == os.Getenv("GITHUB_WORKSPACE") {
		return os.Getenv("GITHUB_REPOSITORY")
	}
	return ""
}

// Run scans the configured path and writes the SARIF file when one is asked for.
func Run(cfg *config.Config) (*audit.Report, error) {
	reg, err := registry.Load()
	if err != nil {
		return nil, fmt.Errorf("load registry: %w", err)
	}
	rep, err := audit.ScanRepo(reg, cfg.Path, cfg.IgnoreRules, repoName(cfg.Path))
	if err != nil {
		return nil, err
	}
	if cfg.SARIFFile != "" {
		data, err := report.SARIF(rep, Version)
		if err != nil {
			return nil, fmt.Errorf("render sarif: %w", err)
		}
		if err := os.WriteFile(cfg.SARIFFile, data, 0o644); err != nil {
			return nil, fmt.Errorf("write sarif: %w", err)
		}
	}
	return rep, nil
}
