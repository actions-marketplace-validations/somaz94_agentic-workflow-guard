package action

import (
	"fmt"

	"github.com/YOUR_USERNAME/YOUR_ACTION/internal/config"
)

// Result holds the output of the action.
type Result struct {
	Content string
}

// Run executes the main action logic.
func Run(cfg *config.Config) (*Result, error) {
	if cfg.InputFile != "" {
		return processFile(cfg.InputFile)
	}
	return &Result{
		Content: "Hello from my-action! Replace this with your logic.",
	}, nil
}

func processFile(path string) (*Result, error) {
	// TODO: Replace with actual file processing logic.
	return &Result{
		Content: fmt.Sprintf("Processed file: %s", path),
	}, nil
}
