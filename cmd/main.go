package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/YOUR_USERNAME/YOUR_ACTION/internal/action"
	"github.com/YOUR_USERNAME/YOUR_ACTION/internal/config"
	"github.com/YOUR_USERNAME/YOUR_ACTION/internal/output"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		output.LogWarning("Received shutdown signal, cleaning up...")
		cancel()
	}()

	if err := run(ctx); err != nil {
		output.LogError(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg := config.Load()

	output.LogInfo("Starting action...")
	output.LogInfo(fmt.Sprintf("Output file: %s", cfg.OutputFile))

	select {
	case <-ctx.Done():
		return fmt.Errorf("cancelled")
	default:
	}

	result, err := action.Run(cfg)
	if err != nil {
		return fmt.Errorf("action failed: %w", err)
	}

	if cfg.DryRun {
		output.LogInfo("Dry run mode - preview:")
		fmt.Println(result.Content)
	} else {
		if err := os.WriteFile(cfg.OutputFile, []byte(result.Content), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		output.LogInfo(fmt.Sprintf("Output written to %s", cfg.OutputFile))
	}

	if err := output.SetOutput("result", result.Content); err != nil {
		output.LogWarning(fmt.Sprintf("Failed to set result output: %v", err))
	}
	if err := output.SetOutput("output_file", cfg.OutputFile); err != nil {
		output.LogWarning(fmt.Sprintf("Failed to set output_file output: %v", err))
	}

	output.LogInfo("Action completed successfully")
	return nil
}
